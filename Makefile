# This script is used by the CI environment to build the project.

export SRCROOT=$(shell pwd)
export CABAL=/usr/bin/cabal
export RUNHASKELL=/usr/bin/runhaskell

.PHONY: default
default: all

.PHONY: all
all: build dist

.PHONY: build
build: test configure
	$(CABAL) build

.PHONY: clean
clean:
	$(CABAL) clean

.PHONY: configure
configure: 
	$(CABAL) configure

.PHONY: dist
dist: build
	$(CABAL) sdist

.PHONY: unit-tests
test: 
	$(RUNHASKELL) -i$(SRCROOT)/src/main/haskell -i$(SRCROOT)/src/test/haskell $(GHCFLAGS) $(SRCROOT)/src/test/haskell/Tests.hs

# vim:sts=4:sw=4:ts=4:noet
