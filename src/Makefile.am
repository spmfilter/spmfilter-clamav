AUTOMAKE_OPTIONS = gnu

AM_LDFLAGS = -export-dynamic
pkglibdir = @libdir@/spmfilter
pkglib_LTLIBRARIES = libclamav.la

CLAMAV = main.c
libclamav_la_SOURCES = $(CLAMAV)
libclamav_la_LDFLAGS = $(AM_LDFLAGS)
libclamav_la_LIBADD = @LTLIBOBJS@
