/* $Id$ */

#include <gpgme.h>
#include "internal.h"
#include "conversation.h"
#include "gaim.h"
#include "gtkplugin.h"
#include "grypt.h"
#include "gtkplugin.h"

static gboolean
plugin_load(GaimPlugin *p)
{
	void *h = gaim_conversations_get_handle();

	/* Initialize GPGME */
	if (!grypt_crypto_init())
		return (gboolean)FALSE;

	/* Read last key*/
	bark("Loading previous identity");
	grypt_identity_load();

	/* Add "encrypt/decrypt" icon */
	grypt_gui_add_icon();

	/* Attach callbacks */
	bark("Attaching callbacks");
	gaim_signal_connect(h, "conversation-created",  p, GAIM_CALLBACK(grypt_evt_new_conversation), NULL);
	gaim_signal_connect(h, "deleting-conversation", p, GAIM_CALLBACK(grypt_evt_del_conversation), NULL);
	gaim_signal_connect(h, "received-im-msg",       p, GAIM_CALLBACK(grypt_evt_im_recv), NULL);
	gaim_signal_connect(h, "sent-im-msg",           p, GAIM_CALLBACK(grypt_evt_im_send), NULL);

	return (gboolean)TRUE;
}

static gboolean
plugin_unload(GaimPlugin *p)
{
#if 0
	GList *iter;
	GaimConversation *gaimconv;

	/* Free encryption-session data */
	for (iter = gaim_get_conversations(); iter != NULL; iter = iter->next) {
		gaimconv = (GaimConversation *)iter->data;
		grypt_free_conv(gaimconv);
	}
#endif

	gpgme_release(ctx);
	grypt_free_identities();

	/* gpgme_recipients_release(recipients); */

	return (gboolean)TRUE;
}

static GaimGtkPluginUiInfo ui_info = { grypt_gui_config };

static GaimPluginInfo info = {
	2,						/* api_version */
	GAIM_PLUGIN_STANDARD,				/* type */
	GAIM_GTK_PLUGIN_TYPE,				/* ui_requirement */
	0,						/* flags */
	NULL,						/* dependencies */
	GAIM_PRIORITY_DEFAULT,				/* priority */

	"grypt",					/* id */
	N_("Grypt"),		 			/* name */
	"0.1",						/* version */
	N_("Encryption plugin"),			/* summary */
							/* description */
	N_("Grypt is an encryption plugin for Gaim."),
	"Jared Yanovich <jaredy@closeedge.net>",	/* author */
	"http://www.closeedge.net/",			/* homepage */

	plugin_load,					/* load */
	plugin_unload,					/* unload */
	NULL,						/* destroy */

	&ui_info,					/* ui_info */
	NULL
};

static void
__init_plugin(GaimPlugin *p)
{
}

GAIM_INIT_PLUGIN(grypt, __init_plugin, info);
