plugindir = $(libdir)/gaim

grypt_la_LDFLAGS = -module -avoid-version -lgpgme

if PLUGINS

plugin_LTLIBRARIES = grypt.la 

grypt_la_SOURCES = plugin.c gui.c misc.c grypt.c crypto.c

endif

CFLAGS += $(DEBUG_CFLAGS) -DDATADIR=\"$(datadir)\"


INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/src \
	-DVERSION=\"$(VERSION)\"
