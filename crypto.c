/* $Id$ */

#include <string.h>
#include <stdlib.h>

#include <gpgme.h>
#include <glib.h>
#include <gtk/gtk.h>
#include "gaim.h"
#include "grypt.h"

const char *fingerprint;
GValue **identities;
gpgme_ctx_t ctx;

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
grypt_crypto_toggle(GaimConversation *conv)
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
		if (fingerprint == NULL) {
bark("no fingerprint available");
			return;
		}
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

//		grypt_session_end(conv);

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
grypt_encrypt(GaimConversation *conv, char *plaintext)
{
	gpgme_data_t plaindata, cipherdata;
	gpgme_key_t key, keys[2];
	gpgme_error_t error;
	char *ciphertext;
	size_t len;

	if ((key = (gpgme_key_t)gaim_conversation_get_data(conv,
	    "/grypt/key")) == NULL) {
bark("grypt_encrypt: can't find key");
		return (NULL);
	}

	error = gpgme_data_new_from_mem(&plaindata, plaintext,
	    strlen(plaintext), 0);
	if (error) {
bark("gpgme_data_new_from_mem: %s", gpgme_strerror(error));
		return (NULL);
	}

	error = gpgme_data_new(&cipherdata);
	if (error) {
bark("gpgme_data_new: %s", gpgme_strerror(error));
		return (NULL);
	}

	keys[0] = key;
	keys[1] = NULL;
	error = gpgme_op_encrypt(ctx, keys, 0, plaindata, cipherdata);
	if (error) {
bark("gpgme_op_encrypt: %s", gpgme_strerror(error));
		return (NULL);
	}

	gpgme_data_release(plaindata);
	ciphertext = gpgme_data_release_and_get_mem(cipherdata, &len);
	return (ciphertext);
}

char *
grypt_decrypt(GaimConversation *conv, char *ciphertext)
{
	gpgme_data_t plaindata, cipherdata;
	gpgme_error_t error;
	char *plaintext;
	size_t len;

	error = gpgme_data_new_from_mem(&cipherdata, ciphertext,
	    strlen(ciphertext), 0);
	if (error) {
bark("gpgme_data_new_from_mem: %s", gpgme_strerror(error));
		return (NULL);
	}

	error = gpgme_data_new(&plaindata);
	if (error) {
bark("gpgme_data_new: %s", gpgme_strerror(error));
		return (NULL);
	}

	error = gpgme_op_decrypt(ctx, cipherdata, plaindata);
	if (error) {
bark("gpgme_op_decrypt: %s", gpgme_strerror(error));
		return (NULL);
	}

	gpgme_data_release(cipherdata);
	plaintext = gpgme_data_release_and_get_mem(plaindata, &len);
	return (plaintext);
}

void
grypt_gather_identities(void)
{
	gpgme_error_t error, eof;
	GValue **v, *u;
	gpgme_key_t k;
	size_t nkeys;

	eof = gpg_error(GPG_ERR_EOF);

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
	if (error != eof)
		bark("gpgme_op_keylist_next: %s [%d:%d]", gpgme_strerror(error), error, eof);

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

		/* Fill fingerprint */
		memset(u, 0, sizeof(GValue));
		g_value_init(u, G_TYPE_STRING);
		g_value_set_string(u, k->subkeys->keyid);

		/* Fill name */
		memset(++u, 0, sizeof(GValue));
		g_value_init(u, G_TYPE_STRING);
		g_value_set_string(u, k->uids->name);

		/* Fill description */
		memset(++u, 0, sizeof(GValue));
		g_value_init(u, G_TYPE_STRING);
		g_value_set_string(u, k->uids->comment);

		/* Fill fingerprint */
		memset(++u, 0, sizeof(GValue));
		g_value_init(u, G_TYPE_STRING);
		g_value_set_string(u, k->subkeys->fpr);

		gpgme_key_release(k);
		*++v = NULL;
	}
	if (error != eof)
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
	free(identities);
	identities = NULL;
bark("done freeing");
}
