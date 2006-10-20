EXTRA_DIST = \
		Makefile.mingw

plugindir = $(libdir)/gaim

grypt_la_LDFLAGS = -module -avoid-version

if PLUGINS

plugin_LTLIBRARIES = grypt.la

grypt_la_SOURCES = crypto.c grypt.c gui.c misc.c plugin.c

grypt_la_LIBADD = $(GTK_LIBS) `gpgme-config --libs`    

endif

AM_CPPFLAGS = \
	-DDATADIR=\"$(datadir)\" \
	-DVERSION=\"$(VERSION)\" \
	-I$(top_srcdir)/libgaim \
	-I$(top_srcdir)/gtk \
	$(DEBUG_CFLAGS) \
	`gpgme-config --cflags` \
	$(GTK_CFLAGS)
