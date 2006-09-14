/* $Id$ */

#include <gpgme.h>
#include "internal.h"
#include "conversation.h"
#include "gaim.h"
#include "gtkplugin.h"
#include "grypt.h"
#include "gtkplugin.h"
#include "version.h"

static gboolean
plugin_load(GaimPlugin *p)
{
	void *h = gaim_conversations_get_handle();

	/* Initialize GPGME */
	if (!grypt_crypto_init())
		return (FALSE);

	grypt_gather_identities();

	/* XXX: read last key */
bark("Loading previous identity");
	if (identities[0])
		fingerprint = g_value_get_string(&identities[0][FPR_COL]);
//	grypt_identity_load();

	/* Attach callbacks */
bark("Attaching callbacks");
	gaim_signal_connect(h, "conversation-created", p,
	    GAIM_CALLBACK(grypt_evt_new_conversation), NULL);
	gaim_signal_connect(h, "receiving-im-msg", p,
	    GAIM_CALLBACK(grypt_evt_im_recv), NULL);
	gaim_signal_connect(h, "sending-im-msg", p,
	    GAIM_CALLBACK(grypt_evt_im_send), NULL);
	return (TRUE);
}

static gboolean
plugin_unload(GaimPlugin *p)
{
#if 0
	GList *iter;
	GaimConversation *conv;

	/* Free encryption-session data */
	for (iter = gaim_get_conversations(); iter != NULL; iter = iter->next) {
		conv = (GaimConversation *)iter->data;
		grypt_free_conv(conv);
	}
#endif

	gpgme_release(ctx);
	grypt_free_identities();

	/* gpgme_recipients_release(recipients); */

	return (TRUE);
}

static GaimGtkPluginUiInfo ui_info = { grypt_gui_config, 0 };

static GaimPluginInfo info = {
	GAIM_PLUGIN_MAGIC,				/* api_version */
	GAIM_MAJOR_VERSION,				/* major */
	GAIM_MINOR_VERSION,				/* minor */
	GAIM_PLUGIN_STANDARD,				/* type */
	GAIM_GTK_PLUGIN_TYPE,				/* ui_requirement */
	0,						/* flags */
	NULL,						/* dependencies */
	GAIM_PRIORITY_DEFAULT,				/* priority */
	"grypt",					/* id */
	N_("Grypt"),		 			/* name */
	GRYPT_VERSION,					/* version */
	N_("Uses GnuPG for AIM encryption."),		/* summary */
	N_("During new conversation, messages are sent "
	    "to establish a secure communication channel "
	    "using GnuPG over AIM with others also using "
	    "this plug-in."),				/* description */
	"Jared Yanovich <jaredy@closeedge.net>",	/* author */
	"http://www.closeedge.net/",			/* homepage */
	plugin_load,					/* load */
	plugin_unload,					/* unload */
	NULL,						/* destroy */
	&ui_info,					/* ui_info */
	NULL,						/* extra_info */
	NULL,						/* prefs info */
	NULL						/* actions */
};

static void
init_plugin(GaimPlugin *p)
{
}

GAIM_INIT_PLUGIN(grypt, init_plugin, info);
