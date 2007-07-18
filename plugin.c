/* $Id$ */

#include <gpgme.h>
#include "internal.h"
#include "conversation.h"
#include "grypt.h"
#include "version.h"
#include "pidgin/gtkplugin.h"

static gboolean
plugin_load(PurplePlugin *p)
{
	void *h = purple_conversations_get_handle();

	/* Initialize GPGME */
	if (!grypt_crypto_init())
		return (FALSE);

	grypt_gather_identities();

	/* XXX: read last identity */
	if (grypt_identities[0])
		grypt_choose(grypt_identities[0]);
//	grypt_identity_load();

	/* Attach callbacks */
	purple_signal_connect(h, "conversation-created", p,
	    PURPLE_CALLBACK(grypt_evt_new_conversation), NULL);
	purple_signal_connect(h, "receiving-im-msg", p,
	    PURPLE_CALLBACK(grypt_evt_im_recv), NULL);
	purple_signal_connect(h, "sending-im-msg", p,
	    PURPLE_CALLBACK(grypt_evt_im_send), NULL);
	purple_signal_connect(h, "buddy-signed-off", p,
	    PURPLE_CALLBACK(grypt_evt_sign_off), NULL);
	return (TRUE);
}

static gboolean
plugin_unload(PurplePlugin *p)
{
	/* Free encryption-session data */
	grypt_peers_free();
	gpgme_release(grypt_ctx);
	grypt_free_identities();
	return (TRUE);
}

static PidginPluginUiInfo ui_info = { grypt_gui_config, 0 };

static PurplePluginInfo info = {
	PURPLE_PLUGIN_MAGIC,				/* api_version */
	PURPLE_MAJOR_VERSION,				/* major */
	PURPLE_MINOR_VERSION,				/* minor */
	PURPLE_PLUGIN_STANDARD,				/* type */
	PIDGIN_PLUGIN_TYPE,				/* ui_requirement */
	0,						/* flags */
	NULL,						/* dependencies */
	PURPLE_PRIORITY_DEFAULT,				/* priority */
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
	NULL,						/* actions */

	NULL,
	NULL,
	NULL,
	NULL
};

static void
init_plugin(PurplePlugin *p)
{
}

PURPLE_INIT_PLUGIN(grypt, init_plugin, info);
