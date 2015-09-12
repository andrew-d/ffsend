V = 0
VFLAG := GO15VENDOREXPERIMENT=1
GOBUILD_0 = @echo "Compiling $@..."; $(VFLAG) go build
GOBUILD_1 = $(VFLAG) go build -v
GOBUILD = $(GOBUILD_$(V))

GOTEST_0 = @$(VFLAG) go test
GOTEST_1 = $(VFLAG) go test -v
GOTEST = $(GOTEST_$(V))

AT_0 := @
AT_1 :=
AT = $(AT_$(V))


.PHONY: all
all: ffsend


ffsend:
	$(GOBUILD) -o $@


.PHONY: test
test:
	$(GOTEST)


.PHONY: clean
clean:
	$(AT)$(RM) ffsend
