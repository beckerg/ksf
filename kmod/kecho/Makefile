
# Copyright (c) 2013,2016-2017,2019 Greg Becker.  All rights reserved.

KMOD    = kecho

SRCS    = ${KMOD}.c svc.c tdp.c xx.c

VPATH = ../lib

.include <bsd.kmod.mk>

CFLAGS	+= -DKSF_MOD=${KMOD} -DKSF_MOD_NAME=\"${KMOD}\"
CFLAGS	+= -I../lib
CFLAGS	+= -march=native

#CFLAGS	+= -DINVARIANTS
#CFLAGS	+= -DDIAGNOSTIC
#CFLAGS	+= -O0 -g

CLEANFILES += cscope.* TAGS ${KMOD}.objdump .depend.*.o
CSCOPE_DIRS ?= . ${VPATH} /usr/src/lib /usr/src/sys
CTAGS = true

.PHONY:	clobber cscope etags tags objdump

clobber: clean

cscope: cscope.out

cscope.out: cscope.files ${HDR} ${SRC}
	cscope -bukq

cscope.files:
	find ${CSCOPE_DIRS} -name \*.[chsSyl] -o -name \*.cpp > $@

objdump:
	objdump -sdwx -Mintel --prefix-addresses ${KMOD}.o > ${KMOD}.objdump

tags etags: TAGS

TAGS: cscope.files
	cat cscope.files | xargs etags -a --members --output=$@
