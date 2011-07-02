
INCLUDES = -I$(VARNISHSRC)/include -I$(VARNISHSRC) -I/usr/include

dist_man_MANS = vmod_secdown.3

vmoddir = $(VMODDIR)
vmod_LTLIBRARIES = libvmod_secdown.la

libvmod_secdown_la_LDFLAGS = -module -export-dynamic -version-info 1:0:0

libvmod_secdown_la_SOURCES = \
	vcc_if.c \
	vcc_if.h \
	vmod_secdown.c \
	md5.c

vcc_if.c vcc_if.h: $(VARNISHSRC)/lib/libvmod_std/vmod.py $(top_srcdir)/src/vmod.vcc
	@PYTHON@ $(VARNISHSRC)/lib/libvmod_std/vmod.py $(top_srcdir)/src/vmod.vcc

EXTRA_DIST = vmod.vcc

CLEANFILES = $(builddir)/vcc_if.c $(builddir)/vcc_if.h

vmod_secdown.3: $(top_srcdir)/README.rst

if HAVE_RST2MAN
	${RST2MAN} $? $@
else
	@echo "========================================"
	@echo "You need rst2man installed to make dist"
	@echo "========================================"
	@false
endif

