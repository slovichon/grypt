plugindir = $(libdir)/pidgin

grypt_la_LDFLAGS = -module -avoid-version

if PLUGINS

plugin_LTLIBRARIES = grypt.la

grypt_la_SOURCES = crypto.c grypt.c gui.c misc.c plugin.c

grypt_la_LIBADD = $(GTK_LIBS) `gpgme-config --libs`    

endif

AM_CPPFLAGS = \
	-DDATADIR=\"$(datadir)\" \
	-I$(top_srcdir)/libpurple \
	-I$(top_builddir)/libpurple \
	-I$(top_srcdir)/pidgin \
	$(DEBUG_CFLAGS) \
	`gpgme-config --cflags` \
	$(GTK_CFLAGS)
