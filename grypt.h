/* $Id$ */

#include <gtk/gtk.h>
#include <gpgme.h>
#include "gaim.h"
#include "conversation.h"
#include "gtkplugin.h"
#include "slist.h"

#define GRYPT_VERSION "2.0.0beta3.1"

#define FPRSIZ 40

/* Peer states. */
#define ST_UN   1 /* Unencrypted */
#define ST_PND  2 /* Pending */
#define ST_EN   3 /* Encrypted */
#define ST_NSUP 4 /* Unsupported, don't even try */

/* Column types for the "select identity" window */
enum {
	KEYID_COL,
	NAME_COL,
	DESC_COL,
	FPR_COL,
	COL_CNT,
};

struct grypt_peer_data {
	char				*gpd_screenname;
	int				 gpd_deny;
	gpgme_key_t			 gpd_key;
	SLIST_ENTRY(grypt_peer_data)	 gpd_link;
};
SLIST_HEAD(grypt_peers, grypt_peer_data);

/* crypto.c */
int			 grypt_crypto_init(void);
char			*grypt_encrypt(gpgme_key_t, const char *);
char			*grypt_decrypt(const char *);
void			 grypt_gather_identities(void);
void			 grypt_free_identities(void);
void			 grypt_choose(GValue *);

/* misc.c */
void	 		 bark(const char *fmt, ...);
void	 		 croak(const char *fmt, ...);

/* gui.c */
GtkWidget		*grypt_gui_config(GaimPlugin *p);
void			 grypt_gui_gather_ids(GtkListStore *);
void			 grypt_gui_id_select_cb(GtkTreeSelection *, gpointer);

/* Grypt peer fetching flags. */
#define GPF_CREAT (1<<0)

/* grypt.c */
struct grypt_peer_data	*grypt_peer_get(const char *, int);
void			 grypt_peers_free(void);
int			 grypt_session_start(struct grypt_peer_data *, const char *);
void			 grypt_evt_new_conversation(GaimConversation *);
void			 grypt_evt_sign_off(GaimBuddy *, void *);
int			 grypt_evt_im_send(GaimAccount *, char *, char **, int *, void *);
int			 grypt_evt_im_recv(GaimAccount *, char **, char **,
				GaimConversation *, int *, void *);

extern struct grypt_peers  grypt_peers;
extern GValue		 **grypt_identities;
extern GValue		  *grypt_identity;
extern char		  *grypt_passphrase;
extern gpgme_ctx_t	   grypt_ctx;
