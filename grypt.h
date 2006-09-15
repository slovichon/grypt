/* $Id$ */

#include <gtk/gtk.h>
#include <gpgme.h>
#include "gaim.h"
#include "conversation.h"
#include "gtkplugin.h"

#define GRYPT_VERSION "2.0.0beta3"

#define FPRSIZ 40

#define ST_UN  1 /* Unencrypted */
#define ST_PND 2 /* Pending */
#define ST_EN  3 /* Encrypted */

/* crypto.c */
int	 grypt_crypto_init(void);
char	*grypt_encrypt(GaimConversation *, char *);
char	*grypt_decrypt(GaimConversation *, char *);
void	 grypt_crypto_toggle(GaimConversation *);
void	 grypt_gather_identities(void);
void	 grypt_free_identities(void);

/* misc.c */
void	 bark(char *fmt, ...);
void	 croak(char *fmt, ...);

/* gui.c */
GtkWidget *grypt_gui_config(GaimPlugin *p);
void	   grypt_gui_gather_ids(GtkListStore *);
void	   grypt_gui_id_select_cb(GtkTreeSelection *, gpointer);
void	   grypt_choose(GValue *);

/* grypt.c */
int	 grypt_session_start(GaimConversation *, char *);
void	 grypt_evt_new_conversation(GaimConversation *);
void	 grypt_evt_del_conversation(GaimConversation *);
void	 grypt_evt_im_send(GaimAccount *, char *, char **, void *);
int	 grypt_evt_im_recv(GaimAccount *, char **, char **,
    GaimConversation *, int *, void *);

/* crypto.c */
extern GValue **identities;
extern const char *fingerprint;
extern char *passphrase;
extern gpgme_ctx_t ctx;

/* Column types for the "select identity" window */
enum {
	KEYID_COL,
	NAME_COL,
	DESC_COL,
	FPR_COL,
	COL_CNT,
};
