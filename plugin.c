/* $Id$ */

#include <gpgme.h>
#include "gaim.h"
#include "gtkplugin.h"
#include "grypt.h"

static gboolean
plugin_load(GaimPlugin *p)
{
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
	gaim_signal_connect(p, event_new_conversation, grypt_evt_new_conversation, NULL);
	gaim_signal_connect(p, event_del_conversation, grypt_evt_del_conversation, NULL);
	gaim_signal_connect(p, event_im_recv, grypt_evt_im_recv, NULL);
	gaim_signal_connect(p, event_im_send, grypt_evt_im_send, NULL);

	return (gboolean)TRUE;
}

static gboolean
plugin_unload(GaimPlugin *p)
{
/*
	GList *iter;
	struct gaim_conversation *gaimconv;
*/
	/* Free encryption-session data */
/*
	for (iter = gaim_get_conversations(); iter != NULL; iter = iter->next)
	{
		gaimconv = (struct gaim_conversation *)iter->data;
		grypt_free_conv(gaimconv);
	}
*/
	gpgme_release(ctx);
	grypt_free_identities();
/*
	gpgme_recipients_release(recipients);
*/
	return (gboolean)TRUE;
}

static GaimGtkPluginUiInfo ui_info = { grypt_gui_config };

static GaimPluginInfo info =
{
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