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
	    "/grypt/state")) != NULL)
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

int
grypt_evt_im_recv(GaimAccount *account, char **sender, char **buf,
    GaimConversation *conv, int *flags, void *data)
{
	char *plaintext, msg[6 + FPRSIZ + 1] = "GRYPT:";
	int ret, *state;

	if ((state = gaim_conversation_get_data(conv,
	    "/grypt/state")) == NULL) {
		/* This shouldn't happen */
		bark("[RECV] in recv_im, state ptr is NULL");
		return (FALSE);
	}

	ret = FALSE;
	switch (*state) {
	case ST_PND:
		/* Session pending, message received, must be the response */
bark("[RECV] Session should be started: received %s from %s", *buf, *sender);
		if (strncmp(*buf, "GRYPT:", 6) == 0 && (*buf)[6] != '\0') {
bark("[RECV] Started with fingerprint %s", *buf + 6);
			if (grypt_session_start(conv, *buf + 6)) {
				*state = ST_EN;
bark("[RECV] encryption enabled");

				// print encryption enabled to window/log
				ret = TRUE;
			}
		} else {
			/* Remote user must not have grypt... */
bark("[RECV] Could not be started");
			*state = ST_UN;
		}
		break;
	case ST_EN:
		/* Decrypt message */
bark("[RECV] Received encrypted message from %s", *sender);
		if (strcmp(*buf, "GRYPT:END") == 0) {
bark("[RECV] Ending encryption");
			/* Request to end encryption */
			*state = ST_UN;
//			grypt_session_end(conv);

			// print encryption disabled to window/log
		} else {
			/* Encrypt, free *text, change buf */
			plaintext = grypt_decrypt(conv, *buf);
bark("[RECV] ciphertext: %s, plaintext: %s", *buf, plaintext);
			if (plaintext)
				*buf = plaintext;
		}
		break;
	default:
bark("[RECV] State must be ST_UN (%s)", *buf);
		if (strncmp(*buf, "GRYPT:", 6) == 0 && (*buf)[6] != '\0') {
bark("[RECV] Received request to start session: %s", *buf);

			if (fingerprint == NULL) {
bark("no fingerprint available");
				break;
			}

			/* Request to initiate crypto */
			if (!grypt_session_start(conv, *buf + 6))
				break;
			*state = ST_EN;
			*buf = NULL;

			strncat(msg, fingerprint, FPRSIZ);
			msg[6 + FPRSIZ] = '\0';

bark("[RECV] encryption enabled, responding (%s)", msg);
			serv_send_im(account->gc, *sender, msg, 0);
		}
		break;
	}
	return (ret);
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
