/* $Id$ */

#include <gtk/gtk.h>
#include <gdk-pixbuf/gdk-pixbuf.h>
#include <gpgme.h>
#include "gaim.h"
#include "gtkplugin.h"
#include "grypt.h"

void grypt_evt_new_conversation(char *name)
{
	struct gaim_conversation *gaimconv = gaim_find_conversation(name);
	int *state;
	GtkWidget *button;

	bark("button created, saving pointer");
	button = (GtkWidget *)grypt_gui_show_button(gaimconv);
	gaim_conversation_set_data(gaimconv, "grypt_button", button);

	bark("saving state");
	state = (int *)malloc(sizeof(int));
	*state = ST_UN;
	gaim_conversation_set_data(gaimconv, "grypt_state", state);
}

void grypt_session_start(struct gaim_conversation *gaimconv, char *fpr)
{
	GpgmeRecipients *rep;

	bark("saving recipients");
	rep = (GpgmeRecipients *)malloc(sizeof(GpgmeRecipients));
	_GA(gpgme_recipients_new(rep), croak("Cannot create new recipients"));
	_GA(gpgme_recipients_add_name_with_validity(*rep, fpr, GPGME_VALIDITY_FULL),
		croak("Couldn't add fingerprint"));
	gaim_conversation_set_data(gaimconv, "grypt_rep", rep);
}

void grypt_evt_del_conversation(struct gaim_conversation *gaimconv)
{
	GtkWidget *button;
	int *state;

	bark("Conversation free request");

	if ((button = (GtkWidget *)gaim_conversation_get_data(gaimconv, "grypt_button")) != NULL)
		gtk_widget_destroy(button);

	bark("button destroyed");

	if ((state = (int *)gaim_conversation_get_data(gaimconv, "grypt_state")) != NULL)
	{
		if (*state == ST_EN)
			grypt_session_end(gaimconv);
		free(state);
	}

	bark("encryption state destroyed");

//	gaim_conversation_set_data(gaimconv, "grypt_button",	(gpointer)NULL);
//	gaim_conversation_set_data(gaimconv, "grypt_state",	(gpointer)NULL);

//	bark("Values overwritten with NULL");
}

void grypt_session_end(struct gaim_conversation *gaimconv)
{
	GpgmeRecipients *rep;

	if ((rep = (GpgmeRecipients *)gaim_conversation_get_data(gaimconv, "grypt_rep")) != NULL)
		gpgme_recipients_release(*rep);

	bark("recipients destroyed");

//	gaim_conversation_set_data(gaimconv, "grypt_rep",	(gpointer)NULL);

//	bark("Values overwritten with NULL");
}

void grypt_evt_im_recv(struct gaim_connection *c, char **who, char **text, guint32 flags)
{
	struct gaim_conversation *gaimconv = gaim_find_conversation(*who);
	int *state = (int *)gaim_conversation_get_data(gaimconv, "grypt_state");

	bark("RECVING %s", *text);

	if (state == NULL)
	{
		/* This shouldn't happen */
		bark("RECV: in recv_im, state ptr is NULL");
		return;
	}

	if (*state == ST_PND)
	{
		/* Session pending, message received, must be the response */
		bark("RECV: Session should be started: received %s from %s", *text, *who);
		if (strncmp(*text, "GRYPT:", 6) == 0 && *text+6 != '\0')
		{
			bark("RECV: Started with fingerprint %s", *text+6);
			grypt_session_start(gaimconv, *text+6);
			*state = ST_EN;
		} else {
			GtkWidget *button;
			/* They must not have this plugin. Oh well. */
			bark("RECV: Could not be started");
			*state = ST_UN;
			button = (GtkWidget *)gaim_conversation_get_data(gaimconv, "grypt_button");
			g_signal_handlers_block_by_func(G_OBJECT(button),
				G_CALLBACK(grypt_crypto_encdec_cb), gaimconv);
			gtk_toggle_button_set_active(
				GTK_TOGGLE_BUTTON(button), FALSE);
			g_signal_handlers_unblock_by_func(G_OBJECT(button),
				G_CALLBACK(grypt_crypto_encdec_cb), gaimconv);
		}
	} else if (*state == ST_EN) {
		/* Decrypt message */
		bark("RECV: Received encrypted message from %s", *who);

		if (strncmp(*text, "GRYPT:END", 9) == 0)
		{
			bark("RECV: Ending encryption");
			/* Request to end encryption */
			*state = ST_UN;
			grypt_session_end(gaimconv);
			/* Flip button state */
		} else {
			/* Encrypt, free *text, change *text*/
		}
	} else {
		bark("State must be ST_UN (%s)", *text);
		
		if (strncmp(*text, "GRYPT:", 6) == 0)
		{
			bark("Looks like incoming matches GRYPT:");

			if (*text+6 != '\0') {
		char msg[6+FPRSIZ+1] = "GRYPT:";

		bark("Received request to start session: %s", *text);
		/* Request to initiate crypto */
		grypt_session_start(gaimconv, *text+6);
		*state = ST_EN;
		*text = NULL;

		strncat(msg, fingerprint, FPRSIZ);
		msg[7+FPRSIZ] = '\0';

		bark("Responding with message %s", msg);

		serv_send_im(c, *who, msg, -1, 0);
	}}}
}

void grypt_evt_im_send(struct gaim_connection *c, char **who, char **text)
{
	struct gaim_conversation *gaimconv = gaim_find_conversation(who);
	int *state = (int *)gaim_conversation_get_data(gaimconv, "grypt_state");

	bark("SENDING %s", *text);

	if (state == NULL)
	{
		/* This shouldn't happen */
		bark("SENT: in send_im, state ptr is NULL");
		return;
	}

	if (*state == ST_PND)
	{
		/* This shouldn't happen... */
	} else if (*state == ST_EN) {
		/* Send message */
		bark("SENT: Sent encrypted message to %s", who);
	}
}