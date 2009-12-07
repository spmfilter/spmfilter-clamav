AC_INIT(spmfilter-clamav,0.1)
AM_INIT_AUTOMAKE
AM_ENABLE_SHARED(yes)
AC_PROG_CC
AM_PROG_LIBTOOL

PKG_CHECK_MODULES([spmfilter],[libspmfilter >= 0.3])
CFLAGS="$CFLAGS $spmfilter_CFLAGS" 
LDFLAGS="$LDFLAGS $spmfilter_LIBS" 

AC_OUTPUT(Makefile src/Makefile)
