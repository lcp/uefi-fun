CC		= $(CROSS_COMPILE)gcc
LD		= $(CROSS_COMPILE)ld
OBJCOPY		= $(CROSS_COMPILE)objcopy

ARCH		= $(shell $(CC) -dumpmachine | cut -f1 -d- | sed s,i[3456789]86,ia32,)
OBJCOPY_GTE224  = $(shell expr `$(OBJCOPY) --version |grep ^"GNU objcopy" | sed 's/^.*\((.*)\|version\) //g' | cut -f1-2 -d.` \>= 2.24)

LIB_PATH	= /usr/lib64

EFI_INCLUDE	:= /usr/include/efi
EFI_INCLUDES	= -nostdinc -I$(EFI_INCLUDE) -I$(EFI_INCLUDE)/$(ARCH) -I$(EFI_INCLUDE)/protocol
EFI_PATH	:= /usr/lib64/

LIB_GCC		= $(shell $(CC) -print-libgcc-file-name)
EFI_LIBS	= -lefi -lgnuefi $(LIB_GCC)

EFI_CRT_OBJS 	= $(EFI_PATH)/crt0-efi-$(ARCH).o
EFI_LDS		= elf_$(ARCH)_efi.lds

CFLAGS		= -ggdb -O0 -fno-stack-protector -fno-strict-aliasing -fpic \
		  -fshort-wchar -Wall -Wsign-compare -Werror -fno-builtin \
		  -Werror=sign-compare -ffreestanding -std=gnu89 \
		  -I$(shell $(CC) -print-file-name=include) \
		  $(EFI_INCLUDES)

ifeq ($(ARCH),x86_64)
	CFLAGS	+= -mno-mmx -mno-sse -mno-red-zone -nostdinc \
		-maccumulate-outgoing-args \
		-DEFI_FUNCTION_WRAPPER -DGNU_EFI_USE_MS_ABI \
		-DNO_BUILTIN_VA_FUNCS
endif
ifeq ($(ARCH),ia32)
	CFLAGS	+= -mno-mmx -mno-sse -mno-red-zone -nostdinc \
		-maccumulate-outgoing-args -m32
endif

LDFLAGS		= --hash-style=sysv -nostdlib -znocombreloc -T $(EFI_LDS) -shared -Bsymbolic -L$(EFI_PATH) -L$(LIB_PATH) -LCryptlib -LCryptlib/OpenSSL $(EFI_CRT_OBJS) --build-id=sha1

TARGET	= WriteAppend.efi
OBJS	= WriteAppend.o
SOURCES	= WriteAppend.c

all: $(TARGET)

WriteAppend.o: $(SOURCES)

WriteAppend.so: $(OBJS)
	$(LD) -o $@ $(LDFLAGS) $^ $(EFI_LIBS)

FORMAT		?= --target efi-app-$(ARCH)

%.efi: %.so
ifneq ($(OBJCOPY_GTE224),1)
	$(error objcopy >= 2.24 is required)
endif
	$(OBJCOPY) -j .text -j .sdata -j .data \
		-j .dynamic -j .dynsym  -j .rel* \
		-j .rela* -j .reloc -j .eh_frame \
		-j .vendor_cert \
		$(FORMAT)  $^ $@
	$(OBJCOPY) -j .text -j .sdata -j .data \
		-j .dynamic -j .dynsym  -j .rel* \
		-j .rela* -j .reloc -j .eh_frame \
		-j .debug_info -j .debug_abbrev -j .debug_aranges \
		-j .debug_line -j .debug_str -j .debug_ranges \
		-j .note.gnu.build-id \
		$(FORMAT) $^ $@.debug

clean:
	rm -f *.debug *.o *.so *.efi
