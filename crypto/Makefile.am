lib_LTLIBRARIES = libdove_crypto.la
libdove_crypto_la_SOURCES = dv_mem.c pem/dv_pem.c x509/dv_x509.c
libdove_crypto_la_LDFLAGS = -version-info 1

AM_CPPFLAGS = -I$(srcdir)/../include
AM_CFLAGS = -Wall -Werror
AUTOMAKE_OPTIONS = foreign subdir-objects
