/* Steal the hexdump code from shim to dump the load option */

#include <efi.h>
#include <efilib.h>

#define isprint(c) ((c) >= 0x20 && (c) <= 0x7e)

static inline unsigned long
prepare_hex(const void *data, INTN size, char *buf, unsigned int position)
{
	char hexchars[] = "0123456789abcdef";
	int offset = 0;
	unsigned long i;
	unsigned long j;
	unsigned long ret;

	unsigned long before = (position % 16);
	unsigned long after = (before+size >= 16) ? 0 : 16 - (before+size);

	for (i = 0; i < before; i++) {
		buf[offset++] = 'X';
		buf[offset++] = 'X';
		buf[offset++] = ' ';
		if (i == 7)
			buf[offset++] = ' ';
	}
	for (j = 0; j < 16 - after - before; j++) {
		uint8_t d = ((uint8_t *)data)[j];
		buf[offset++] = hexchars[(d & 0xf0) >> 4];
		buf[offset++] = hexchars[(d & 0x0f)];
		if (i+j != 15)
			buf[offset++] = ' ';
		if (i+j == 7)
			buf[offset++] = ' ';
	}
	ret = 16 - after - before;
	j += i;
	for (i = 0; i < after; i++) {
		buf[offset++] = 'X';
		buf[offset++] = 'X';
		if (i+j != 15)
			buf[offset++] = ' ';
		if (i+j == 7)
			buf[offset++] = ' ';
	}
	buf[offset] = '\0';
	return ret;
}

static inline void
prepare_text(const void *data, INTN size, char *buf, unsigned int position)
{
	int offset = 0;
	unsigned long i;
	unsigned long j;

	unsigned long before = position % 16;
	unsigned long after = (before+size > 16) ? 0 : 16 - (before+size);

	if (size == 0) {
		buf[0] = '\0';
		return;
	}
	for (i = 0; i < before; i++)
		buf[offset++] = 'X';
	buf[offset++] = '|';
	for (j = 0; j < 16 - after - before; j++) {
		if (isprint(((uint8_t *)data)[j]))
			buf[offset++] = ((uint8_t *)data)[j];
		else
			buf[offset++] = '.';
	}
	buf[offset++] = size > 0 ? '|' : 'X';
	buf[offset] = '\0';
}

/*
 * variadic hexdump formatted
 * think of it as: printf("%s%s\n", vformat(fmt, ap), hexdump(data,size));
 */
static inline void
vhexdumpf(const CHAR16 *const fmt, const void *data, unsigned long size, INTN at,
	  va_list ap)
{
	unsigned long display_offset = at;
	unsigned long offset = 0;

	while (offset < size) {
		char hexbuf[49];
		char txtbuf[19];
		unsigned long sz;

		sz = prepare_hex(data+offset, size-offset, hexbuf,
				 (unsigned long)data+offset);
		if (sz == 0)
			return;

		prepare_text(data+offset, size-offset, txtbuf,
			     (unsigned long)data+offset);
		if (fmt && fmt[0] != 0)
			VPrint(fmt, ap);
		Print(L"%08lx  %a  %a\n", display_offset, hexbuf, txtbuf);

		display_offset += sz;
		offset += sz;
	}
}

/*
 * hexdump formatted
 * think of it as: printf("%s%s", format(fmt, ...), hexdump(data,size)[lineN]);
 */
static inline void
hexdumpf(const CHAR16 *const fmt, const void *data, unsigned long size,
	 INTN at, ...)
{
	va_list ap;

	va_start(ap, at);
	vhexdumpf(fmt, data, size, at, ap);
	va_end(ap);
}

static inline void
hexdump(const void *data, unsigned long size)
{
	hexdumpf(L"", data, size, (intptr_t)data);
}

VOID
efi_pause ()
{
	EFI_INPUT_KEY Key;

	WaitForSingleEvent (ST->ConIn->WaitForKey, 0);
	uefi_call_wrapper(ST->ConIn->ReadKeyStroke, 2, ST->ConIn, &Key);
}

EFI_STATUS
efi_main (EFI_HANDLE image, EFI_SYSTEM_TABLE *systab)
{
	EFI_STATUS efi_status;
	EFI_LOADED_IMAGE *li = NULL;

	InitializeLib(image, systab);

	efi_status = uefi_call_wrapper(BS->HandleProtocol, 3,
				       image, &LoadedImageProtocol,
				       (VOID **) &li);
	if (EFI_ERROR(efi_status)) {
		Print (L"Failed to get load options: %r\n", efi_status);
		return efi_status;
	}

	Print (L"LoadOptionsSize: %d\n", li->LoadOptionsSize);
	if (li->LoadOptionsSize > 0)
		hexdump (li->LoadOptions, li->LoadOptionsSize);

	Print (L"\nPress any key to continue\n");
	efi_pause();

	return EFI_SUCCESS;
}
