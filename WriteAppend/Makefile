EFIFILES = WriteAppend.efi

export TOPDIR	:= $(shell pwd)/

include Make.rules

all: $(EFIFILES)

clean:
	rm -f $(EFIFILES) $(BINARIES) *.o *.so
