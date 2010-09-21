SRCROOT = $(shell pwd)

CABAL   = cabal
FIND    = find
HC      = ghc
HPC     = hpc

HCFLAGS =

MAIN_SRC  = $(foreach d,$(shell $(FIND) src/main/haskell/Network -type d),$(wildcard $(d)/*.hs))
TEST_HOAUTH = dist/bin/test_hoauth
TEST_SRC    = $(foreach d,$(shell $(FIND) src/test/haskell/Test/Network -type d),$(wildcard $(d)/*.hs))

.PHONY: default
default: compile

.PHONY: dist
dist:
	$(CABAL) configure && $(CABAL) sdist

.PHONY: default
default: compile

.PHONY: compile
compile: $(addsuffix .o,$(basename $(MAIN_SRC)))

.PHONY: compile-hpc
compile-hpc: HCFLAGS += -fhpc
compile-hpc: $(addsuffix .o,$(basename $(MAIN_SRC)))

.PHONY: test
test: $(TEST_HOAUTH)
	$(TEST_HOAUTH)

.PHONY: test-hpc
test-hpc: compile-hpc $(TEST_HOAUTH)
	-@$(TEST_HOAUTH) >/dev/null
	$(HPC) markup --destdir=dist/hpc test_hoauth.tix
	$(HPC) report test_hoauth.tix

.PHONY: clean
clean:
	$(CABAL) clean
	$(FIND) src/main/haskell -name \*.o -exec rm -f {} \;
	$(FIND) src/main/haskell -name \*.hi -exec rm -f {} \;
	$(FIND) src/test/haskell -name \*.o -exec rm -f {} \;
	$(FIND) src/test/haskell -name \*.hi -exec rm -f {} \;
	rm -f -r dist
	rm -f -r *.tix
	rm -f -r .hpc

$(TEST_HOAUTH): src/test/haskell/test_hoauth.hs $(MAIN_SRC) $(TEST_SRC)
	@[ -d dist ] || mkdir dist
	@[ -d dist/bin ] || mkdir dist/bin
	$(HC) -o $(@) -isrc/test/haskell -isrc/main/haskell --make $(HCFLAGS) $(<)

.SUFFIXES: .o .hs
.hs.o: 
	$(HC) -c --make -o $(@) -isrc/main/haskell -isrc/test/haskell $(HCFLAGS) $(<)
