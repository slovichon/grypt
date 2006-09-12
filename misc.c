/* $Id$ */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gpgme.h>
#include "grypt.h"

void
grypt_identity_load(void)
{
}

void
grypt_identity_save(void)
{
}

void
bark(char *fmt, ...)
{
#ifdef GRYPT_DEBUG
	va_list ap;
	va_start(ap, fmt);
	fprintf(stderr, "[GRYPT DEBUG] ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	fflush(stderr);
	va_end(ap);
#endif
}

void
flog(char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	fprintf(stderr, "[GRYPT ERROR] ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	fflush(stderr);
	va_end(ap);
}

void
croak(char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	fprintf(stderr, "[GRYPT FATAL] ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	if (errno)
		fprintf(stderr, "Error: %s\n", strerror(errno));
	va_end(ap);
	exit(1);
}
