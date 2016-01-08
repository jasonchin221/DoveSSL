lib_LTLIBRARIES = libdove_ssl.la
libdove_ssl_la_SOURCES = dv_ssl_lib.c dv_tls.c dv_ssl_rsa.c dv_tls_bio.c \
						 dv_tls1_2_proto.c dv_bio.c \
						 dv_bio_linux.c
libdove_ssl_la_LDFLAGS = -version-info 1
libdove_ssl_la_LIBADD = $(srcdir)/../crypto/libdove_crypto.la

AM_CPPFLAGS = -I$(srcdir)/../include
AM_CFLAGS = -Wall -Werror
AUTOMAKE_OPTIONS = foreign subdir-objects
