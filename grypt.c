/* $Id$ */

#include <string.h>
#include <stdlib.h>

#include <gtk/gtk.h>
#include <gdk-pixbuf/gdk-pixbuf.h>
#include <gpgme.h>
#include "gaim.h"
#include "gtkplugin.h"
#include "grypt.h"

void
grypt_evt_new_conversation(GaimConversation *conv)
{
	GtkWidget *button;
	int *state;

bark("saving button");
	button = grypt_gui_show_button(conv);
	gaim_conversation_set_data(conv, "/grypt/button", button);

bark("saving state");
	if ((state = malloc(sizeof(*state))) == NULL)
		croak("couldn't malloc");
	*state = ST_UN;
	gaim_conversation_set_data(conv, "/grypt/state", state);
}

void
grypt_session_start(GaimConversation *conv, char *fpr)
{
	gpgme_error_t error;
	gpgme_key_t key;

	error = gpgme_get_key(ctx, fpr, &key, 0);
	if (error || key == NULL || key->uids->uid == NULL)
		croak("can't get key for %s [%s]", fpr,
		    gpgme_strerror(error));
	gaim_conversation_set_data(conv, "/grypt/key", key);
}

void
grypt_evt_del_conversation(GaimConversation *conv)
{
	int *state;
	void *p;

bark("Conversation free request");
	if ((p = gaim_conversation_get_data(conv,
	    "/grypt/button")) != NULL)
		gtk_widget_destroy(p);

bark("button destroyed");
	if ((state = gaim_conversation_get_data(conv,
	    "/grypt/state")) != NULL) {
		if (*state == ST_EN)
			grypt_session_end(conv);
		free(state);
	}

#if 0
	bark("encryption state destroyed");

	gaim_conversation_set_data(conv, "/grypt/button", NULL);
	gaim_conversation_set_data(conv, "/grypt/state",  NULL);

	bark("Values overwritten with NULL");
#endif
}

void
grypt_session_end(GaimConversation *conv)
{
	void *p;

bark("destroying key");
	if ((p = gaim_conversation_get_data(conv,
	    "/grypt/key")) != NULL)
		gpgme_key_release(p);

#if 0
bark("Values overwritten with NULL");
	gaim_conversation_set_data(conv, "/grypt/key", NULL);
#endif
}

void
grypt_evt_im_recv(GaimAccount *account, char **sender, char **buf,
    GaimConversation *conv, int *flags, void *data)
{
	char msg[6 + FPRSIZ + 1] = "GRYPT:";
	int *state;

bark("RECEIVED %s", *buf);
	if ((state = (int *)gaim_conversation_get_data(conv,
	    "/grypt/state")) == NULL) {
		/* This shouldn't happen */
		bark("[RECV] in recv_im, state ptr is NULL");
		return;
	}

	switch (*state) {
	case ST_PND:
		/* Session pending, message received, must be the response */
bark("[RECV] Session should be started: received %s from %s", *buf, *sender);
		if (strncmp(*buf, "GRYPT:", 6) == 0 && (*buf)[6] != '\0') {
bark("[RECV] Started with fingerprint %s", *buf + 6);
			grypt_session_start(conv, *buf + 6);
			*state = ST_EN;
		} else {
			GtkWidget *button;
			/* Remote user must not have grypt. */
bark("[RECV] Could not be started");
			*state = ST_UN;
			button = (GtkWidget *)gaim_conversation_get_data(conv,
			    "/grypt/button");
			g_signal_handlers_block_by_func(G_OBJECT(button),
			    G_CALLBACK(grypt_crypto_encdec_cb), conv);
			gtk_toggle_button_set_active(
			    GTK_TOGGLE_BUTTON(button), FALSE);
			g_signal_handlers_unblock_by_func(G_OBJECT(button),
			    G_CALLBACK(grypt_crypto_encdec_cb), conv);
		}
		break;
	case ST_EN:
		/* Decrypt message */
bark("[RECV] Received encrypted message from %s", *sender);
		if (strcmp(*buf, "GRYPT:END") == 0) {
bark("[RECV] Ending encryption");
			/* Request to end encryption */
			*state = ST_UN;
			grypt_session_end(conv);
			/* Flip button state */
		} else {
			/* Encrypt, free *text, change buf */
		}
		break;
	default:
bark("[RECV] State must be ST_UN (%s)", *buf);
		if (strncmp(*buf, "GRYPT:", 6) == 0 && (*buf)[6] != '\0') {
bark("[RECV] Received request to start session: %s", *buf);
			/* Request to initiate crypto */
			grypt_session_start(conv, *buf + 6);
			*state = ST_EN;
			*buf = NULL;

			strncat(msg, fingerprint, FPRSIZ);
			msg[6 + FPRSIZ] = '\0';

bark("[RECV] Responding with message %s", msg);
			serv_send_im(account->gc, *sender, msg, 0);
		}
		break;
	}
}

void
grypt_evt_im_send(GaimAccount *account, char *rep, char **buf, void *data)
{
	GaimConversation *conv;
	int *state;

bark("SENDING %s", *buf);
	if ((conv = gaim_find_conversation_with_account(GAIM_CONV_TYPE_IM,
	    rep, account)) == NULL) {
bark("can't find conversation for %s", rep);
		return;
	}

	if ((state = (int *)gaim_conversation_get_data(conv,
	    "/grypt/state")) == NULL) {
		/* This shouldn't happen */
bark("SENT: in send_im, state ptr is NULL");
		return;
	}

	switch (*state) {
	case ST_PND:
		/* This shouldn't happen... */
		break;
	case ST_EN:
bark("should encrypt message to %s", rep);
		break;
	}
}
