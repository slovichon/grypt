/* $Id$ */

#include <string.h>
#include <stdlib.h>

#include <gpgme.h>
#include <glib.h>
#include <gtk/gtk.h>
#include "gaim.h"
#include "grypt.h"

gpgme_ctx_t ctx;
GValue **identities = NULL;
char fingerprint[FPRSIZ + 1];

int
grypt_crypto_init(void)
{
	gpgme_error_t error;

bark("Initializing GPGME");
	error = gpgme_new(&ctx);
	if (error) {
		bark("unable to initalize gpgme: %s",
		    gpgme_strerror(error));
		return (FALSE);
	}

	gpgme_set_armor(ctx, 1);
	return (TRUE);
}

void
grypt_crypto_encdec_cb(GtkWidget *w, GaimConversation *conv)
{
	char msg[6 + FPRSIZ + 1] = "GRYPT:";
	GaimConnection *gaimconn;
	int *state;

	state = (int *)gaim_conversation_get_data(conv, "/grypt/state");
	if (state == NULL) {
		/* This shouldn't happen */
		bark("couldn't retrieve encryption state from conv");
		return;
	}

	switch (*state) {
	case ST_UN: /* Initiate encryption */
		strncat(msg, fingerprint, FPRSIZ);
		msg[FPRSIZ + 6] = '\0';

bark("Set state to ST_PND");
		*state = ST_PND;

bark("Sending message %s", msg);
		gaimconn = gaim_conversation_get_gc(conv);
		serv_send_im(gaimconn, gaim_conversation_get_name(conv),
		    msg, 0);
		break;
	case ST_EN: /* End encryption */
bark("Set state to ST_UN");
		*state = ST_UN;

		grypt_session_end(conv);

		gaimconn = gaim_conversation_get_gc(conv);
		serv_send_im(gaimconn, gaim_conversation_get_name(conv),
		    "GRYPT:END", 0);
		break;
	case ST_PND:
		/* Cancel initiation */
bark("Cancel, set state to ST_UN");
		*state = ST_UN;
		break;
	}
}

char *
encrypt(char *plaintext, gpgme_key_t key)
{
	gpgme_data_t plain, cipher;
	gpgme_error_t error;
	gpgme_key_t keys[2];
	char *ciphertext;
	size_t len;

	error = gpgme_data_new_from_mem(&plain, plaintext,
	    strlen(plaintext), 0);
	if (error) {
bark("gpgme_data_new_from_mem: %s", gpgme_strerror(error));
		return (NULL);
	}

	error = gpgme_data_new(&cipher);
	if (error) {
bark("gpgme_data_new: %s", gpgme_strerror(error));
		return (NULL);
	}

	keys[0] = key;
	keys[1] = NULL;
	error = gpgme_op_encrypt(ctx, keys, 0, plain, cipher);
	if (error) {
bark("gpgme_op_encrypt: %s", gpgme_strerror(error));
		return (NULL);
	}

	gpgme_data_release(plain);
	ciphertext = gpgme_data_release_and_get_mem(cipher, &len);
	return (ciphertext);
}

char *
decrypt(char *msg, gpgme_key_t key)
{
	return "decrypted...";
}

void
grypt_gather_identities(void)
{
	gpgme_error_t error;
	gpgme_key_t k;
	size_t nkeys;
	GValue **v, *u;

	/* We only need to do this once */
	if (identities != NULL) {
bark("Already gathered identities");
		return;
	}

	nkeys = 0;

	error = gpgme_op_keylist_start(ctx, NULL, 1);
	if (error) {
bark("gpgme_op_keylist_start: %s", gpgme_strerror(error));
		return;
	}

	for (;;) {
		error = gpgme_op_keylist_next(ctx, &k);
		if (error || k == NULL)
			break;
		nkeys++;
		gpgme_key_release(k);
	}
	if (error != GPG_ERR_EOF)
		bark("gpgme_op_keylist_next: %s [%d:%d]", gpgme_strerror(error), error, GPG_ERR_EOF);

	if ((v = identities = calloc(nkeys, sizeof(GValue *))) == NULL)
		croak("calloc");
	error = gpgme_op_keylist_end(ctx);

bark("Gathering secret identities");
	error = gpgme_op_keylist_start(ctx, NULL, 1);
	if (error) {
bark("gpgme_op_keylist_start: %s", gpgme_strerror(error));
		return;
	}

	for (;;) {
		error = gpgme_op_keylist_next(ctx, &k);
		if (error || k == NULL)
			break;

bark("%s: %s <%s>\n", k->subkeys->fpr, k->uids->name, k->uids->comment);

		if ((u = *v = calloc(COL_CNT, sizeof(GValue))) == NULL)
			croak("calloc");

bark("Filling fingerprint");
		/* Fill fingerprint */
		memset(u, 0, sizeof(GValue));
		g_value_init(u, G_TYPE_STRING);
		g_value_set_string(u, k->subkeys->fpr);

		/* Fill name */
		memset(++u, 0, sizeof(GValue));
		g_value_init(u, G_TYPE_STRING);
		g_value_set_string(u, k->uids->name);

		/* Fill description */
		memset(++u, 0, sizeof(GValue));
		g_value_init(u, G_TYPE_STRING);
		g_value_set_string(u, k->uids->comment);

		gpgme_key_release(k);
		*++v = NULL;
	}
	if (error != GPG_ERR_EOF)
		bark("gpgme_op_keylist_next: %s", gpgme_strerror(error));
	error = gpgme_op_keylist_end(ctx);
}

void
grypt_free_identities(void)
{
	GValue **v;

	if (identities == NULL)
		return;

bark("Freeing identities");
	for (v = identities; *v != NULL; v++)
		if (*v != NULL)
			free(*v);
bark("done freeing");
}
