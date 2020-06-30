SUBDIRS = bin

ifeq ($(shell uname -s),FreeBSD)
SUBDIRS += kmod
endif

CSCOPE_DIRS ?= . /usr/src/lib /usr/src/sys

.NOTPARALLEL:

.PHONY: all ${SUBDIRS} ${MAKECMDGOALS}

all ${MAKECMDGOALS}: ${SUBDIRS}

clobber: ${SUBDIRS}
	rm -f cscope.* TAGS

cscope: cscope.out

cscope.out: cscope.files ${HDR} ${SRC}
	cscope -bukq

cscope.files:
	find ${CSCOPE_DIRS} -name \*.[chsSyl] -o -name \*.cpp > $@

tags etags: TAGS

TAGS: cscope.files
	cat cscope.files | xargs etags -a --members --output=$@

${SUBDIRS}:
	${MAKE} -C $@ ${MAKECMDGOALS}
