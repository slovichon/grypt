/* $Id$ */

#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include <gtk/gtk.h>
#include <gdk-pixbuf/gdk-pixbuf.h>
#include <gpgme.h>
#include "gaim.h"
#include "gtkplugin.h"
#include "grypt.h"
#include "protocols/oscar/oscar.h"

/* copied from protocols/oscar/oscar.c */
typedef struct _OscarData OscarData;
struct _OscarData {
	OscarSession *sess;
	OscarConnection *conn;

	guint cnpa;
	guint paspa;
	guint emlpa;
	guint icopa;

	gboolean iconconnecting;
	gboolean set_icon;

	GSList *create_rooms;

	gboolean conf;
	gboolean reqemail;
	gboolean setemail;
	char *email;
	gboolean setnick;
	char *newsn;
	gboolean chpass;
	char *oldp;
	char *newp;

	GSList *oscar_chats;
	GSList *direct_ims;
	GSList *file_transfers;
	GHashTable *buddyinfo;
	GSList *requesticon;

	gboolean killme;
	gboolean icq;
	guint icontimer;
	guint getblisttimer;
	guint getinfotimer;
	gint timeoffset;

	struct {
		guint maxwatchers; /* max users who can watch you */
		guint maxbuddies; /* max users you can watch */
		guint maxgroups; /* max groups in server list */
		guint maxpermits; /* max users on permit list */
		guint maxdenies; /* max users on deny list */
		guint maxsiglen; /* max size (bytes) of profile */
		guint maxawaymsglen; /* max size (bytes) of posted away message */
	} rights;
};

static int
grypt_aim_sncmp(const char *sn1, const char *sn2)
{
	if ((sn1 == NULL) || (sn2 == NULL))
		return -1;

	do {
		while (*sn2 == ' ')
			sn2++;
		while (*sn1 == ' ')
			sn1++;
		if (toupper(*sn1) != toupper(*sn2))
			return 1;
	} while ((*sn1 != '\0') && sn1++ && sn2++);

	return 0;
}

static aim_userinfo_t *
grypt_aim_locate_finduserinfo(OscarSession *sess, const char *sn)
{
	aim_userinfo_t *cur = NULL;

	if (sn == NULL)
		return NULL;

	cur = sess->locate.userinfo;

	while (cur != NULL) {
		if (grypt_aim_sncmp(cur->sn, sn) == 0)
			return cur;
		cur = cur->next;
	}

	return NULL;
}

/* ******************************************************** */

static int
grypt_possible(GaimConversation *conv)
{
	aim_userinfo_t *userinfo;
	GaimConnection *gc;
	OscarData *od;

	if (strcmp(gaim_account_get_protocol_id(conv->account),
	    "prpl-oscar") != 0)
		return (FALSE);

	gc = gaim_conversation_get_gc(conv);
	od = gc->proto_data;
	userinfo = grypt_aim_locate_finduserinfo(od->sess, conv->name);
	if (userinfo == NULL ||
	    (userinfo->capabilities & AIM_CAPS_GRYPT) == 0)
		return (FALSE);
	return (TRUE);
}

void
grypt_evt_new_conversation(GaimConversation *conv)
{
	int *state;

	if (!grypt_possible(conv))
		return;
bark("EVENT NEW CONV");

	if ((state = malloc(sizeof(*state))) == NULL)
		croak("couldn't malloc");
	*state = ST_UN;
	gaim_conversation_set_data(conv, "/grypt/state", state);
	grypt_crypto_toggle(conv);
}

void
grypt_evt_del_conversation(GaimConversation *conv)
{
	gpgme_key_t key;
	int *state;

	if ((state = gaim_conversation_get_data(conv,
	    "/grypt/state")) != NULL && *state != ST_UN)
		grypt_crypto_toggle(conv);
	free(state);
	if ((key = gaim_conversation_get_data(conv,
	    "/grypt/key")) != NULL)
		gpgme_key_release(key);
}

int
grypt_session_start(GaimConversation *conv, char *fpr)
{
	gpgme_error_t error;
	gpgme_key_t key;

	if ((key = gaim_conversation_get_data(conv,
	    "/grypt/key")) != NULL)
		return (TRUE);

	error = gpgme_get_key(ctx, fpr, &key, 0);
	if (error || key == NULL || key->uids->uid == NULL) {
		bark("can't get key for %s [%s]", fpr,
		    gpgme_strerror(error));
		return (FALSE);
	}
	gaim_conversation_set_data(conv, "/grypt/key", key);
	return (TRUE);
}

void
grypt_evt_im_recv(GaimAccount *account, char **sender, char **buf,
    GaimConversation *conv, int *flags, void *data)
{
	char *p, *plaintext, *bufp, msg[BUFSIZ];
	int *state;

	bufp = *buf;
	if (strncmp(*buf, "GRYPT:", 6) == 0)
		*buf = NULL;

	if (conv == NULL) {
		/*
		 * A grypt message was sent but we can't
		 * do anything since we can't store, so
		 * let the "new IM" event handle that part
		 * and let this part be rehandled later.
		 */
		return;
	}

	if ((state = gaim_conversation_get_data(conv,
	    "/grypt/state")) == NULL)
		/* XXX send reject msg back */
		return;

	if (fingerprint == NULL)
		/* XXX send reject msg back */
		return;

	switch (*state) {
	case ST_PND:
		/*
		 * Session pending, active establishment,
		 * response may have been received.
		 */
bark("[RECV] Session should be started: received %s from %s", bufp, *sender);
		if (strcmp(bufp, "GRYPT:END") == 0) {
bark("request to prematurely end crypto session satisfied successfully");
			*state = ST_UN;
			*buf = NULL;
			return;
		} else if (strncmp(bufp, "GRYPT:", 6) == 0) {
			if ((p = strrchr(bufp, ':')) == NULL) {
				bark("internal error: can't find colon (%s)", bufp);
				*state = ST_UN;
				*buf = NULL;
				return;
			}
			p++;
			if (grypt_session_start(conv, p)) {
				*state = ST_EN;
				if (strncmp(bufp, "GRYPT:REQ:", 10) == 0) {
					/*
					 * Our request wasn't seen;
					 * send it again.
					 */
					snprintf(msg, sizeof(msg),
					    "GRYPT:RES:%s", fingerprint);

bark("our request was neglected, reSEND (%s)", msg);
					serv_send_im(gaim_conversation_get_gc(conv),
					    gaim_conversation_get_name(conv), msg, 0);
				}
			} else {
				bark("can't start session");
			}
		} else {
			/* Remote user may not have grypt... */
bark("[RECV] expected GRYPT message");
		}
		break;
	case ST_EN:
		/* Decrypt message */
bark("[RECV] Received encrypted message from %s", *sender);
		if (strcmp(bufp, "GRYPT:END") == 0) {
bark("[RECV] Ending encryption");
			/* Request to end encryption */
			*state = ST_UN;
//			grypt_session_end(conv);

			// print encryption disabled to window/log
		} else {
			/* Encrypt, free *text, change buf */
			plaintext = grypt_decrypt(conv, bufp);
bark("[RECV] ciphertext: %s, plaintext: %s", bufp, plaintext);
			if (plaintext)
				*buf = plaintext;
		}
		break;
	case ST_UN:
		/* XXX if we receive an encrypted msg, send GRYPT:END */
		if (strncmp(bufp, "GRYPT:REQ:", 6) == 0) {
			*buf = NULL;
bark("[RECV] Received request to start session: %s", bufp);
			p = strrchr(bufp, ':');
			if (p == NULL) {
				bark("internal error: can't find colon (%s)", bufp);
				*state = ST_UN;
				return;
			}
			p++;
			/* Request to initiate crypto */
			if (!grypt_session_start(conv, p))
				break;
			*state = ST_EN;

			snprintf(msg, sizeof(msg), "GRYPT:RES:%s", fingerprint);

bark("[RECV] encryption enabled, respond, SEND (%s)", msg);
			serv_send_im(account->gc, *sender, msg, 0);
		} else if (strncmp(bufp, "----- BEGIN PGP MESSAGE -----", 29) == 0) {
			*state = ST_EN;
			grypt_crypto_toggle(conv);
			*state = ST_UN;
		}
		break;
	}
}

void
grypt_evt_im_send(GaimAccount *account, char *rep, char **buf, void *data)
{
	GaimConversation *conv;
	char *ciphertext;
	int *state;

	if ((conv = gaim_find_conversation_with_account(GAIM_CONV_TYPE_IM,
	    rep, account)) == NULL)
		return;
	if ((state = gaim_conversation_get_data(conv,
	    "/grypt/state")) == NULL)
		return;

bark("sending, state=%d", *state);
	switch (*state) {
	case ST_EN:
		ciphertext = grypt_encrypt(conv, *buf);
bark("send: plaintext: %s, ciphertext: <%s>", *buf, ciphertext);
		if (ciphertext)
			*buf = ciphertext;
		break;
	}
}
