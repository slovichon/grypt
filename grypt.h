/* $Id$ */

#ifndef GRYPT_H
#define GRYPT_H

#include <gtk/gtk.h>
#include <gpgme.h>
#include "gaim.h"
#include "conversation.h"
#include "gtkplugin.h"

#define GRYPT_DEBUG
#define GRYPT_VERSION "0.1"

#define TRUE  1
#define FALSE 0

#define FPRSIZ 40

#define ST_UN  1 /* Unencrypted */
#define ST_PND 2 /* Pending */
#define ST_EN  3 /* Encrypted */

/* GPGME assert macro */
#define _GA(c, d)						\
	if ((gpgmerr = (c)) != GPGME_No_Error) {		\
		bark("GPGME error: %s\nCode (line %d): %s",	\
		gpgme_strerror(gpgmerr), __LINE__, #c);		\
		d;						\
	}

/* crypto.c */
int grypt_crypto_init(void);
char *encrypt(char *msg, GpgmeRecipients *);
char *decrypt(char *msg, GpgmeRecipients *);
void grypt_crypto_encdec_cb(GtkWidget *, GaimConversation *);
void grypt_gather_identities(void);
void grypt_free_identities(void);

/* misc.c */
void grypt_identity_load(void);
void grypt_identity_save(void);
void bark(char *fmt, ...);				/* Debug print */
void flog(char *fmt, ...);				/* Error print */
void croak(char *fmt, ...);				/* Die */

/* gui.c */
void grypt_gui_add_icon(void);
GtkWidget *grypt_gui_config(GaimPlugin *p);
void grypt_gui_gather_ids(GtkListStore *);		/* Gather GPG identities */
GtkWidget *grypt_gui_show_button(GaimConversation *);
void grypt_gui_id_select_cb(GtkTreeSelection *, gpointer);

/* grypt.c */
void grypt_evt_new_conversation(char *);
void grypt_evt_del_conversation(GaimConversation *);
void grypt_evt_im_recv(GaimConnection *, char **, char **, guint *, void *);
void grypt_evt_im_send(GaimConnection *, char **, char **, void *);
void grypt_session_end(GaimConversation *);
void grypt_session_start(GaimConversation *, char *);

/* crypto.c */
extern GpgmeCtx ctx;
extern GpgmeError gpgmerr;
extern GValue **identities;
extern char fingerprint[];

/* Column types for the "select identity" window */
enum {
	FPR_COL,
	NAME_COL,
	DESC_COL,
	COL_CNT,
};

#endif /* GRYPT_H */
