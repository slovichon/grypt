/* $Id$ */

#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <gpgme.h>
#include <glib.h>
#include <gtk/gtk.h>
#include "gaim.h"
#include "internal.h"
#include "request.h"
#include "grypt.h"

const char *fingerprint;
char *passphrase;
GValue **identities;
gpgme_ctx_t ctx;

static gpgme_error_t
grypt_passphrase(void *hook, const char *uid_hint,
    const char *passphrase_info, int prev_was_bad, int fd)
{
	ssize_t sz;

	if (passphrase == NULL) {
		sz = write(fd, "\n", 1);
		return (1);
	}

	sz = strlen(passphrase);
	if (write(fd, passphrase, sz) != sz) {
		bark("write");
		// while (write != 1);
		sz = write(fd, "\n", 1);
	}
	return (0);
}

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
	gpgme_set_passphrase_cb(ctx, grypt_passphrase, NULL);
	return (TRUE);
}

static void
grypt_choose_cb(gpointer data, GaimRequestFields *fields)
{
	const char *f;
	char *newpass;
	GValue *id;
	size_t len;

	id = data;
	f = gaim_request_fields_get_string(fields, "passphrase");
	len = strlen(f);
	if ((newpass = malloc(len + 2)) == NULL)
		croak("malloc");
	strncpy(newpass, f, len);
	newpass[len] = '\n';
	newpass[len + 1] = '\0';
	free(passphrase);
	passphrase = newpass;
	fingerprint = g_value_get_string(&id[FPR_COL]);
}

void
grypt_choose(GValue *id)
{
	GaimRequestFieldGroup *group;
	GaimRequestFields *fields;
	GaimRequestField *field;
	char buf[BUFSIZ];

	fields = gaim_request_fields_new();

	group = gaim_request_field_group_new(NULL);
	gaim_request_fields_add_group(fields, group);

	field = gaim_request_field_string_new("passphrase",
	    _("_Passphrase"), NULL, FALSE);
	gaim_request_field_set_type_hint(field, "passphrase");
	gaim_request_field_set_required(field, TRUE);
	gaim_request_field_string_set_masked(field, TRUE);
	gaim_request_field_group_add_field(group, field);

	snprintf(buf, sizeof(buf), "%s '%s' (%s) %s",
	    _("Please enter the secret GPG passphrase for the"),
	    g_value_get_string(&id[NAME_COL]),
	    g_value_get_string(&id[KEYID_COL]), _("identity."));
	gaim_request_fields(gaim_get_blist(), _("Enter GPG Passphrase"),
	    NULL, buf, fields, _("OK"), G_CALLBACK(grypt_choose_cb),
	    _("Cancel"), NULL, id);
}

void
grypt_crypto_toggle(GaimConversation *conv)
{
	char msg[6 + FPRSIZ + 1] = "GRYPT:";
	GaimConnection *gaimconn;
	int *state;

	state = gaim_conversation_get_data(conv, "/grypt/state");
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
	char *ciphertext, *p;
	size_t len;

	if ((key = gaim_conversation_get_data(conv,
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
	p = gpgme_data_release_and_get_mem(cipherdata, &len);
	if ((ciphertext = malloc(len + 1)) == NULL)
		croak("malloc");
	strncpy(ciphertext, p, len);
	free(p);
	ciphertext[len] = '\0';
	return (ciphertext);
}

char *
grypt_decrypt(GaimConversation *conv, char *ciphertext)
{
	gpgme_data_t plaindata, cipherdata;
	gpgme_error_t error;
	char *plaintext, *p;
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

bark("decrypting...");
	error = gpgme_op_decrypt(ctx, cipherdata, plaindata);
	if (error) {
bark("gpgme_op_decrypt: %s", gpgme_strerror(error));
		return (NULL);
	}
bark("done");

	gpgme_data_release(cipherdata);
	p = gpgme_data_release_and_get_mem(plaindata, &len);
	if ((plaintext = malloc(len + 1)) == NULL)
		croak("malloc");
	strncpy(plaintext, p, len);
	free(p);
	plaintext[len] = '\0';
	return (plaintext);
}

void
grypt_gather_identities(void)
{
	gpgme_error_t error;
	GValue **v, *u;
	gpgme_key_t k;
	size_t nkeys;

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
	if (gpg_err_code(error) != GPG_ERR_EOF)
		bark("gpgme_op_keylist_next: %s", gpgme_strerror(error));

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
	if (gpg_err_code(error) != GPG_ERR_EOF)
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
