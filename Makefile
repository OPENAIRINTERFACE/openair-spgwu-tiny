SHELL := /bin/bash
GTP_INTERFACE?=$(GTP_INTERFACE)
UDP_INTERFACE?=$(UDP_INTERFACE)
GNUMAKEFLAGS=--no-print-directory

.PHONY: help

#############################################################################
## Help
#############################################################################
help:
	@echo "Usage: make [comando]"
	@echo
	@echo "Comandos:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "- \033[36m%-30s\033[0m %s\n", $$1, $$2}'


#############################################################################
## Build dependencies
#############################################################################
setup:
	build/scripts/build_upf  -I -f -V


#############################################################################
## Install package
#############################################################################
install:
	build/scripts/build_upf -V -b Debug
	

#############################################################################
## Clean all build files
#############################################################################
clean:
	echo "Cleaning S/P-GW-U: generated configuration files, obj files, executable" && \
    rm -Rf build/spgw_u/build  2>&1 && \
    mkdir -m 777 -p -v build



