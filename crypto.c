/* $Id$ */

#include <gpgme.h>
#include <glib.h>
#include <gtk/gtk.h>
#include "gaim.h"
#include "grypt.h"

GpgmeCtx ctx;
GpgmeError gpgmerr;
GValue **identities = NULL;
char fingerprint[FPRSIZ+1];

int grypt_crypto_init()
{
	bark("Initializing GPGME");
	_GA(gpgme_new(&ctx), return FALSE);

	gpgme_set_armor(ctx, 1);

/*
	bark("Initializing recipients");
	_GA(gpgme_recipients_new(&recipients), return (gboolean)FALSE);
*/

	return TRUE;
}

void grypt_crypto_encdec_cb(GtkWidget *w, GaimConversation *gaimconv)
{
	GaimConnection *gaimconn;
	int *state = gaim_conversation_get_data(gaimconv, "grypt_state");
	if (state == NULL)
	{
		/* This shouldn't happen */
		flog("couldn't retrieve encryption state from convo");
		return;
	}
	switch (*state)
	{
		case ST_UN:
		{
			char msg[6+FPRSIZ+1] = "GRYPT:";

			strncat(msg, fingerprint, FPRSIZ);
			msg[FPRSIZ+6] = '\0';

			/* Initiate encryption */
			bark("Set state to ST_PND");
			*state = ST_PND;

			bark("Sending message %s", msg);
			gaimconn = gaim_conversation_get_gc(gaimconv);
			serv_send_im(gaimconn,
				(char *)gaim_conversation_get_name(gaimconv),
				msg, -1, 0);

			break;
		}

		case ST_EN:
			/* End encryption */
			bark("Set state to ST_UN");
			*state = ST_UN;

			grypt_session_end(gaimconv);

			gaimconn = gaim_conversation_get_gc(gaimconv);
			serv_send_im(gaimconn,
				(char *)gaim_conversation_get_name(gaimconv),
				"GRYPT:END", -1, 0);
			break;

		case ST_PND:
			/* Cancel initiation */
			bark("Cancel, set state to ST_UN");
			*state = ST_UN;
			break;
	}
}

char *encrypt(char *plaintext, GpgmeRecipients *rep)
{
	GpgmeData plain, cipher;
	char *ciphertext;
	int len;

	_GA(gpgme_data_new_from_mem(&plain, plaintext, strlen(plaintext), 0), return NULL);
	_GA(gpgme_data_new(&cipher), return NULL);
	_GA(gpgme_op_encrypt(ctx, *rep, plain, cipher), return NULL);
	gpgme_data_release(plain);
	ciphertext = gpgme_data_release_and_get_mem(cipher, &len);

	return ciphertext;
}

char *decrypt(char *msg, GpgmeRecipients *rep)
{
}

void grypt_gather_identities(void)
{
	GpgmeKey k;
	size_t keys = 0;
	GValue **v, *u;

	/* We only need to do this once */
	if (identities != NULL)
	{
		bark("Already gathered identities");
		return;
	}

	_GA(gpgme_op_keylist_start(ctx, NULL, 1), return);
	while ((gpgmerr = gpgme_op_keylist_next(ctx, &k)) == GPGME_No_Error)
	{
		keys++;
		gpgme_key_release(k);
	}
	if (gpgmerr == GPGME_EOF)
	{
		bark("Finished counting identities successfully (%d)", keys);
		/*gpgmerr = GPGME_No_Error;*/
	} else
		bark("Cannot list identities: %s", gpgme_strerror(gpgmerr));

	if ((v = identities = (GValue **)calloc(keys, sizeof(GValue *))) == NULL)
		croak("Couldn't calloc()");

	bark("Gathering secret identities");
	/* Gather secret keys (identities) */
	_GA(gpgme_op_keylist_start(ctx, NULL, 1), return);
	while ((gpgmerr = gpgme_op_keylist_next(ctx, &k)) == GPGME_No_Error)
	{
		bark("%s: %s <%s>\n",
			gpgme_key_get_string_attr(k, GPGME_ATTR_FPR, 0, 0),
			gpgme_key_get_string_attr(k, GPGME_ATTR_NAME, 0, 0),
			gpgme_key_get_string_attr(k, GPGME_ATTR_COMMENT, 0, 0));

		if ((u = *v = (GValue *)calloc(COL_CNT, sizeof(GValue))) == NULL)
			croak("Couldn't calloc()");

		bark("Filling fingerprint");
		/* Fill fingerprint */
		memset(u, 0, sizeof(GValue));
		g_value_init(u, G_TYPE_STRING);
		g_value_set_string(u,
			gpgme_key_get_string_attr(k, GPGME_ATTR_FPR, 0, 0));

		/* Fill name */
		memset(++u, 0, sizeof(GValue));
		g_value_init(u, G_TYPE_STRING);
		g_value_set_string(u,
			gpgme_key_get_string_attr(k, GPGME_ATTR_NAME, 0, 0));

		/* Fill description */
		memset(++u, 0, sizeof(GValue));
		g_value_init(u, G_TYPE_STRING);
		g_value_set_string(u,
			gpgme_key_get_string_attr(k, GPGME_ATTR_COMMENT, 0, 0));

		gpgme_key_release(k);
		*++v = NULL;
	}
	if (gpgmerr == GPGME_EOF)
	{
		bark("Finished listing identities successfully");
		/*gpgmerr = GPGME_No_Error;*/
	} else
		bark("Cannot list identities: %s", gpgme_strerror(gpgmerr));
}

void grypt_free_identities(void)
{
	GValue **v;

	if (identities == NULL)
		return;

	bark("Freeing identities");
	for (v = identities; *v != NULL; v++)
	{
		if (*v != NULL)
		{
//			bark("Freeing identity");
			free(*v);
//			bark("Freed");
		}
	}
}
