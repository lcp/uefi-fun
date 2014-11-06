EFIFILES = ReadArgs.efi HashTest.efi InputOutput.efi SetMode.efi QueryTextIn.efi

export TOPDIR	:= $(shell pwd)/

include Make.rules

all: $(EFIFILES)

clean:
	rm -f $(EFIFILES) *.o *.so

FORCE:



