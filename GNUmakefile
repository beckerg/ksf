SUBDIRS = bin kmod

.PHONY: all ${SUBDIRS} ${MAKECMDGOALS}

all ${MAKECMDGOALS}: ${SUBDIRS}

${SUBDIRS}:
	${MAKE} -C $@ ${MAKECMDGOALS}
