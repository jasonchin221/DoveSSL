AC_INIT([dovessl], [1.0], [liu_yt@neusoft.com])
AM_INIT_AUTOMAKE([-Wall -Werror])
AC_PROG_CC
LT_INIT
AC_PROG_LIBTOOL
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])

AC_ARG_WITH(libxml2_includes,
			[  --with-libxml2-includes=DIR    libxml2 include directory],
			[with_libxml2_includes="$withval"],
			[with_libxml2_includes=no])

AC_ARG_WITH(libxml2_libraries,
			[  --with-libxml2-libraries=DIR   libxml2 library directory],
			[with_libxml2_libraries="$withval"],
			[with_libxml2_libraries=no])

AC_ARG_WITH(libssl_includes,
			[  --with-libssl-includes=DIR    openssl include directory],
			[with_libssl_includes="$withval"],
			[with_libssl_includes=no])

AC_ARG_WITH(libssl_libraries,
			[  --with-libssl-libraries=DIR   openssl library directory],
			[with_libssl_libraries="$withval"],
			[with_libssl_libraries=no])

CPPFLAGS="${CPPFLAGS} -I/usr/local/include -I/usr/local/include/libxml2 -I/usr/include/libxml2"

CPPFLAGS="${CPPFLAGS} -I/usr/local/include"

if test "$with_libxml2_includes" != "no"; then
	CPPFLAGS="${CPPFLAGS} -I${with_libxml2_includes}"
fi

if test "$with_libssl_includes" != "no"; then
	CPPFLAGS="${CPPFLAGS} -I${with_libssl_includes}"
fi

LIBS="${LIBS} -L/usr/local/lib"

if test "$with_libxml2_libraries" != "no"; then
	LIBS="${LIBS} -L${with_libxml2_libraries}"
fi

if test "$with_libssl_libraries" != "no"; then
	LIBS="${LIBS} -L${with_libssl_libraries}"
fi

LXML2=""
AC_CHECK_LIB([xml2], [xmlDocGetRootElement], , LXML2="no")

if test "$LXML2" = "no"; then
    echo
    echo "   ERROR!  libxml2 library not found, go get it from"
    echo "   http://www.xmlsoft.org/downloads.html"
    echo "   or use the --with-libxml2-* options, if you have it installed"
    echo "   in unusual place"
    exit
fi

LSSL=""
AC_CHECK_LIB([crypto], [OPENSSL_config], , LSSL="no")
AC_CHECK_LIB([ssl], [SSL_library_init], , LSSL="no")
if test "$LSSL" = "no"; then
    echo
    echo "   ERROR!  openssl library not found, go get it from"
    echo "   http://www.openssl.org/source/"
    echo "   or use the --with-libssl-* options, if you have it installed"
    echo "   in unusual place"
    exit
fi

LSSL=""
AC_CHECK_HEADERS([openssl/ssl.h], , LSSL="no")
AC_CHECK_HEADERS([openssl/evp.h], , LSSL="no")
AC_CHECK_HEADERS([openssl/conf.h], , LSSL="no")
AC_CHECK_HEADERS([openssl/err.h], , LSSL="no")
AC_CHECK_HEADERS([openssl/engine.h], , LSSL="no")

if test "$LSSL" = "no"; then
    echo
    echo "   ERROR!  openssl headers not found, go get it from"
    echo "   http://www.openssl.org/source/"
    echo "   or use the --with-libssl-* options, if you have it installed"
    echo "   in unusual place"
    exit
fi

LXML2=""
AC_CHECK_HEADERS([libxml/xmlmemory.h], , LXML2="no")
AC_CHECK_HEADERS([libxml/parser.h], , LXML2="no")

if test "$LXML2" = "no"; then
    echo
    echo "   ERROR!  libxml2 headers not found, go get it from"
    echo "   http://www.xmlsoft.org/downloads.html"
    echo "   or use the --with-libxml2-* options, if you have it installed"
    echo "   in unusual place"
    exit
fi

AC_CONFIG_FILES([
				 Makefile
				 tls/Makefile
				 crypto/Makefile
				 test/Makefile
				 ])

AC_OUTPUT
