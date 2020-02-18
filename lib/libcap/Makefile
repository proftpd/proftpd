## This libcap (for proftpd) is originally from libcap, at:
##   https://github.com/mhiramat/libcap.git.
## This interface is SPECIFIC TO THE LINUX 2.2 KERNEL!!!  IT IS NOT GUARANTEED
## TO WORK ON ANY PRIOR OR LATER VERSION (ie: 2.1.x or 2.3.x).
## If this library stops working, please contact core@proftpd.org.

#
# defines
#
topdir=$(shell pwd)/..
include ../../Make.rules

KERNEL_HEADERS=/usr/include
LIBTITLE=libcap

#
# Library version
#
LIBNAME=$(LIBTITLE).so
STALIBNAME=$(LIBTITLE).a
#

FILES=cap_alloc cap_proc cap_extint cap_flag cap_text cap_file

INCLS=libcap.h cap_names.h $(INCS)
OBJS=$(addsuffix .o, $(FILES))

all: $(STALIBNAME)

_makenames: _makenames.c cap_names.list.h
	$(CC) $(CFLAGS) $< -o $@

cap_names.h: _makenames
	./_makenames > cap_names.h

cap_names.list.h: Makefile $(KERNEL_HEADERS)/linux/capability.h
	@echo "=> making $@ from $(KERNEL_HEADERS)/linux/capability.h"
	perl -e 'while ($$l=<>) { if ($$l =~ /^\#define[ \t](CAP[_A-Z]+)[ \t]+([0-9]+)\s+$$/) { $$tok=$$1; $$val=$$2; $$tok =~ tr/A-Z/a-z/; print "{\"$$tok\",$$val},\n"; } }' $(KERNEL_HEADERS)/linux/capability.h | fgrep -v 0x > $@

$(STALIBNAME): $(OBJS)
	$(AR) rcs $@ $^
	$(RANLIB) $@

%.o: %.c $(INCLS)
	$(CC) $(CFLAGS) $(IPATH) -c $< -o $@

cap_text.o: cap_text.c $(INCLS)
	$(CC) $(CFLAGS) $(IPATH) -c $< -o $@

install: all
	mkdir -p -m 0755 $(FAKEROOT)$(INCDIR)/sys
	install -m 0644 include/sys/capability.h $(FAKEROOT)$(INCDIR)/sys
	-/sbin/ldconfig

clean:
	rm -f $(OBJS) $(LIBNAME)* $(STALIBNAME)
	rm -f cap_names.h cap_names.list.h _makenames
