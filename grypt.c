/* $Id$ */

#define _GNU_SOURCE /* asprintf */
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include <gtk/gtk.h>
#include <gdk-pixbuf/gdk-pixbuf.h>
#include <gpgme.h>
#include "grypt.h"
#include "conversation.h"
#include "protocols/oscar/oscar.h"
#include "slist.h"

struct grypt_peers grypt_peers;

/* copied from protocols/oscar/oscar.c */
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
grypt_aim_locate_finduserinfo(OscarData *od, const char *sn)
{
	aim_userinfo_t *cur = NULL;

	if (sn == NULL)
		return NULL;

	cur = od->locate.userinfo;

	while (cur != NULL) {
		if (grypt_aim_sncmp(cur->sn, sn) == 0)
			return cur;
		cur = cur->next;
	}

	return NULL;
}

/* ******************************************************** */

static int
grypt_possible(PurpleAccount *ga, const char *name)
{
	aim_userinfo_t *userinfo;
	PurpleConnection *gc;
	OscarData *od;

	if (strcmp(purple_account_get_protocol_id(ga), "prpl-oscar") != 0)
		return (FALSE);

	gc = purple_account_get_connection(ga);
	od = gc->proto_data;
	userinfo = grypt_aim_locate_finduserinfo(od, name);
	if (userinfo == NULL ||
	    (userinfo->capabilities & OSCAR_CAPABILITY_GRYPT) == 0)
		return (FALSE);
	return (TRUE);
}

void
grypt_evt_new_conversation(PurpleConversation *conv)
{
	struct grypt_peer_data *gpd;
	char msg[BUFSIZ];

	if (!grypt_possible(purple_conversation_get_account(conv),
	    purple_conversation_get_name(conv)))
		return;

	if (grypt_identity == NULL)
		return;

	gpd = grypt_peer_get(purple_conversation_get_name(conv), GPF_CREAT);
	if (gpd->gpd_key == NULL && !gpd->gpd_deny) {
		snprintf(msg, sizeof(msg), "GRYPT:REQ:%s",
		    g_value_get_string(&grypt_identity[FPR_COL]));
		serv_send_im(purple_conversation_get_gc(conv),
		    purple_conversation_get_name(conv), msg, 0);
	}
	if (gpd->gpd_deny == 1) {
		snprintf(msg, sizeof(msg), "GRYPT:PING:REQ");
		serv_send_im(purple_conversation_get_gc(conv),
		    purple_conversation_get_name(conv), msg, 0);
	}
}

int
grypt_session_start(struct grypt_peer_data *gpd, const char *fpr)
{
	gpgme_error_t error;

	if (gpd->gpd_key)
		gpgme_key_release(gpd->gpd_key);

	error = gpgme_get_key(grypt_ctx, fpr, &gpd->gpd_key, 0);
	if (error || gpd->gpd_key == NULL || gpd->gpd_key->uids->uid == NULL) {
		gpd->gpd_key = NULL;
		bark("can't get key for %s [%s]", fpr,
		    gpgme_strerror(error));
		return (FALSE);
	}
	return (TRUE);
}

int
grypt_evt_im_recv(PurpleAccount *account, char **sender, char **buf,
    PurpleConversation *conv, int *flags, void *data)
{
	char *plaintext, *bufp, msg[BUFSIZ];
	struct grypt_peer_data *gpd;

	if (!grypt_possible(account, *sender))
		return (0);

	bufp = *buf;
	if (strncmp(bufp, "GRYPT:", 6) == 0)
		*buf = NULL;

	if (grypt_identity == NULL) {
		if (strncmp(bufp, "GRYPT:", 6) == 0 &&
		    strcmp(bufp, "GRYPT:DENY") != 0) {
			snprintf(msg, sizeof(msg), "GRYPT:DENY");
bark("no identity, telling peer to give up (%s)", msg);
			serv_send_im(purple_conversation_get_gc(conv),
			    purple_conversation_get_name(conv), msg, 0);
		}
		return (0);
	}

	gpd = grypt_peer_get(*sender, GPF_CREAT);
	if (strcmp(bufp, "GRYPT:DENY") == 0)
		gpd->gpd_deny = 2;
	else if (strncmp(bufp, "GRYPT:", 6) == 0)
		gpd->gpd_deny = 0;
	else
		gpd->gpd_deny = 1;

	if (strncmp(bufp, "GRYPT:ENC:", 10) == 0) {
		plaintext = grypt_decrypt(&bufp[10]);
		if (plaintext) {
			*flags |= PURPLE_MESSAGE_ENCRYPTED;
			free(bufp);
			bufp = *buf = plaintext;
			if (gpd->gpd_key == NULL) {
				snprintf(msg, sizeof(msg), "GRYPT:REQ:%s",
				    g_value_get_string(&grypt_identity[FPR_COL]));
				serv_send_im(purple_account_get_connection(account),
				    *sender, msg, 0);
			}
		}
	} else if (strncmp(bufp, "GRYPT:REQ:", 10) == 0) {
		if (grypt_session_start(gpd, &bufp[10])) {
			snprintf(msg, sizeof(msg), "GRYPT:RES:%s",
			    g_value_get_string(&grypt_identity[FPR_COL]));
bark("[RECV] request received, responding (%s)", msg);
			serv_send_im(account->gc, *sender, msg, 0);
		}
	} else if (strncmp(bufp, "GRYPT:RES:", 10) == 0) {
		grypt_session_start(gpd, &bufp[10]);
	} else if (strcmp(bufp, "GRYPT:PING:REQ") == 0) {
		snprintf(msg, sizeof(msg), "GRYPT:PING:RES");
		serv_send_im(account->gc, *sender, msg, 0);
	}
	return (0);
}

int
grypt_evt_im_send(PurpleAccount *account, char *rep, char **buf, int *flags, void *data)
{
	struct grypt_peer_data *gpd;
	char msg[BUFSIZ];
	char *ciphertext;

	if (!grypt_possible(account, rep))
		return (0);

	gpd = grypt_peer_get(rep, GPF_CREAT);
	if (gpd->gpd_deny)
		return (0);
	if (gpd->gpd_key) {
		ciphertext = grypt_encrypt(gpd->gpd_key, *buf);
		if (ciphertext) {
			*flags |= PURPLE_MESSAGE_ENCRYPTED;
			free(*buf);
			if (asprintf(buf, "GRYPT:ENC:%s",
			    ciphertext) == -1)
				croak("asprintf");
			free(ciphertext);
		}
	} else {
		if (grypt_identity) {
			snprintf(msg, sizeof(msg), "GRYPT:RES:%s",
			    g_value_get_string(&grypt_identity[FPR_COL]));
bark("[RECV] request received, responding (%s)", msg);
			serv_send_im(account->gc, rep, msg, 0);
		}
	}
	return (0);
}

int
grypt_evt_sign_off(PurpleBuddy *buddy, void *data)
{
	struct grypt_peer_data *gpd;

	gpd = grypt_peer_get(buddy->name, 0);
	if (gpd) {
		gpgme_key_release(gpd->gpd_key);
		gpd->gpd_key = NULL;
		gpd->gpd_deny = 0;
	}
	return (0);
}

struct grypt_peer_data *
grypt_peer_get(const char *name, int flags)
{
	struct grypt_peer_data *gpd;

	SLIST_FOREACH(gpd, &grypt_peers, gpd_link)
		if (strcmp(gpd->gpd_screenname, name) == 0)
			return (gpd);
	if ((flags & GPF_CREAT) == 0)
		return (NULL);
	if ((gpd = malloc(sizeof(*gpd))) == NULL)
		croak("malloc");
	memset(gpd, 0, sizeof(*gpd));
	if ((gpd->gpd_screenname = strdup(name)) == NULL)
		croak("strdup");
	SLIST_INSERT_HEAD(&grypt_peers, gpd, gpd_link);
	return (gpd);
}

void
grypt_peers_free(void)
{
	struct grypt_peer_data *gpd, *next;

	for (gpd = SLIST_FIRST(&grypt_peers); gpd; gpd = next) {
		next = SLIST_NEXT(gpd, gpd_link);
		free(gpd->gpd_screenname);
		if (gpd->gpd_key)
			gpgme_key_release(gpd->gpd_key);
		free(gpd);
	}
	SLIST_INIT(&grypt_peers);
}
