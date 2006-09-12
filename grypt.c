/* $Id$ */

#include <string.h>

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

	/* bark("button created, saving pointer"); */
	button = (GtkWidget *)grypt_gui_show_button(conv);
	gaim_conversation_set_data(conv, "grypt_button", button);

	/* bark("saving state"); */
	if ((state = (int *)malloc(sizeof(int))) == NULL)
		croak("couldn't malloc");
	*state = ST_UN;
	gaim_conversation_set_data(conv, "grypt_state", state);
}

void
grypt_session_start(GaimConversation *conv, char *fpr)
{
	gpgme_recipient_t rep;

	/* bark("saving recipients"); */
	if ((rep = (gpgme_recipient_t *)malloc(sizeof(*rep))) == NULL)
		croak("couldn't malloc");
	_GA(gpgme_recipients_new(rep), croak("Cannot create new recipients"));
	_GA(gpgme_recipients_add_name_with_validity(*rep, fpr, GPGME_VALIDITY_FULL),
	    croak("Couldn't add fingerprint"));
	gaim_conversation_set_data(conv, "grypt_rep", rep);
}

void
grypt_evt_del_conversation(GaimConversation *conv)
{
	GtkWidget *button;
	int *state;

	/* bark("Conversation free request"); */

	if ((button = (GtkWidget *)gaim_conversation_get_data(conv,
	    "grypt_button")) != NULL)
		gtk_widget_destroy(button);

	/* bark("button destroyed"); */

	if ((state = (int *)gaim_conversation_get_data(conv, "grypt_state")) != NULL) {
		if (*state == ST_EN)
			grypt_session_end(conv);
		free(state);
	}

#if 0
	bark("encryption state destroyed");

	gaim_conversation_set_data(conv, "grypt_button",	(gpointer)NULL);
	gaim_conversation_set_data(conv, "grypt_state",	(gpointer)NULL);

	bark("Values overwritten with NULL");
#endif
}

void
grypt_session_end(GaimConversation *conv)
{
	gpgme_recipient_t *rep;

	if ((rep = (gpgme_recipient_t *)gaim_conversation_get_data(conv,
	    "grypt_rep")) != NULL)
		gpgme_recipients_release(*rep);

	bark("recipients destroyed");

#if 0
	gaim_conversation_set_data(conv, "grypt_rep",	(gpointer)NULL);

	bark("Values overwritten with NULL");
#endif
}

void
grypt_evt_im_recv(GaimConnection *c, char **who, char **text, guint *flags, void *data)
{
	char msg[6 + FPRSIZ + 1] = "GRYPT:";
	GaimConversation *conv;
	int *state;

	conv = gaim_find_conversation(*who);
	state = (int *)gaim_conversation_get_data(conv, "grypt_state");

	bark("RECEIVED %s", *text);

	if (state == NULL) {
		/* This shouldn't happen */
		bark("[RECV] in recv_im, state ptr is NULL");
		return;
	}

	if (*state == ST_PND) {
		/* Session pending, message received, must be the response */
		bark("[RECV] Session should be started: received %s from %s",
		    *text, *who);
		if (strncmp(*text, "GRYPT:", 6) == 0 && *(*text + 6) != '\0') {
			bark("[RECV] Started with fingerprint %s", *text + 6);
			grypt_session_start(conv, *text + 6);
			*state = ST_EN;
		} else {
			GtkWidget *button;
			/* They must not have this plugin. Oh well. */
			bark("[RECV] Could not be started");
			*state = ST_UN;
			button = (GtkWidget *)gaim_conversation_get_data(conv,
			    "grypt_button");
			g_signal_handlers_block_by_func(G_OBJECT(button),
			    G_CALLBACK(grypt_crypto_encdec_cb), conv);
			gtk_toggle_button_set_active(
			    GTK_TOGGLE_BUTTON(button), FALSE);
			g_signal_handlers_unblock_by_func(G_OBJECT(button),
			    G_CALLBACK(grypt_crypto_encdec_cb), conv);
		}
	} else if (*state == ST_EN) {
		/* Decrypt message */
		bark("[RECV] Received encrypted message from %s", *who);

		if (strncmp(*text, "GRYPT:END", 9) == 0) {
			bark("[RECV] Ending encryption");
			/* Request to end encryption */
			*state = ST_UN;
			grypt_session_end(conv);
			/* Flip button state */
		} else {
			/* Encrypt, free *text, change *text*/
		}
	} else {
		bark("[RECV] State must be ST_UN (%s)", *text);

		if (strncmp(*text, "GRYPT:", 6) == 0 && *(*text + 6) != '\0') {
			bark("[RECV] Received request to start session: %s", *text);
			/* Request to initiate crypto */
			grypt_session_start(conv, *text + 6);
			*state = ST_EN;
			*text = NULL;

			strncat(msg, fingerprint, FPRSIZ);
			msg[6 + FPRSIZ] = '\0';

			bark("[RECV] Responding with message %s", msg);

			serv_send_im(c, *who, msg, 0);
		}
	}
}

void
grypt_evt_im_send(GaimConnection *c, char **who, char **text, void *data)
{
	GaimConversation *conv;
	int *state;

	conv = gaim_find_conversation(who);
	state = (int *)gaim_conversation_get_data(conv, "grypt_state");

	bark("SENDING %s", *text);

	if (state == NULL) {
		/* This shouldn't happen */
		bark("SENT: in send_im, state ptr is NULL");
		return;
	}

	if (*state == ST_PND) {
		/* This shouldn't happen... */
	} else if (*state == ST_EN) {
		/* Send message */
		bark("SENT: Sent encrypted message to %s", who);
	}
}
