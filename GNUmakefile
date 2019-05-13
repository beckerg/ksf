SUBDIRS = bin kmod

CSCOPE_DIRS ?= . /usr/src/lib /usr/src/sys

.PHONY: all ${SUBDIRS} ${MAKECMDGOALS}

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

all ${MAKECMDGOALS}: ${SUBDIRS}

${SUBDIRS}:
	${MAKE} -C $@ ${MAKECMDGOALS}
