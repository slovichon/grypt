EXTRA_DIST = \
		Makefile.mingw

plugindir = $(libdir)/gaim

grypt_la_LDFLAGS = -module -avoid-version `gpgme-config --libs`

if PLUGINS

plugin_LTLIBRARIES = grypt.la

grypt_la_SOURCES = plugin.c gui.c misc.c grypt.c crypto.c

endif

AM_CPPFLAGS = \
	-DDATADIR=\"$(datadir)\" \
	-DVERSION=\"$(VERSION)\" \
	-I$(top_srcdir)/src \
	$(DEBUG_CFLAGS) \
	$(GTK_CFLAGS)
