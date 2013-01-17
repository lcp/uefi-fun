/*
  Some snippets are from James Bottomley's UpdateVars
 */

#include <efi.h>
#include <efilib.h>

EFI_STATUS
argsplit(EFI_HANDLE image, int *argc, CHAR16*** ARGV)
{
	int i, count = 0;
	EFI_STATUS status;
	EFI_LOADED_IMAGE *info;
	CHAR16 *start;

	*argc = 0;

	status = uefi_call_wrapper(BS->HandleProtocol, 3, image, &LoadedImageProtocol, (VOID **) &info);
	if (EFI_ERROR(status)) {
		Print(L"Failed to get arguments\n");
		return status;
	}

	Print (L"Load Option Size: %d\n", info->LoadOptionsSize);

	for (i = 0; i < info->LoadOptionsSize; i += 2) {
		CHAR16 *c = (CHAR16 *)(info->LoadOptions + i);
		if (*c == L' ') {
			(*argc)++;
		} else if (*argc > 0 && *c == L'\0') {
			(*argc)++;
		}
	}

	*ARGV = AllocatePool(*argc * sizeof(char *));
	if (!*ARGV) {
		return EFI_OUT_OF_RESOURCES;
	}
	start = (CHAR16 *)info->LoadOptions;
	(*ARGV)[0] = (CHAR16 *)info->LoadOptions;
	for (i = 0; i < info->LoadOptionsSize; i += 2) {
		CHAR16 *c = (CHAR16 *)(info->LoadOptions + i);
		if (*c == L' ') {
			*c = L'\0';
			(*ARGV)[count++] = start;
			start = c + 1;
		}
	}
	if (count < *argc) {
		(*ARGV)[count] = start;
	}

	return EFI_SUCCESS;
}

EFI_STATUS
efi_main (EFI_HANDLE image, EFI_SYSTEM_TABLE *systab)
{
	EFI_STATUS status;
	int argc, i;
	CHAR16 **ARGV;
	CHAR16 descr[64];

	InitializeLib(image, systab);

	status = argsplit(image, &argc, &ARGV);
	if (status != EFI_SUCCESS) {
		StatusToString (descr, status);
		Print (L"error %s\n", descr);
	}

	Print (L"argc %d\n", argc);

	for (i = 0; i < argc; i++)
		Print (L"argv[%d]: %s\n", i, ARGV[i]);

	Print (L"\nPress any key to continue\n");
	Pause();

	return EFI_SUCCESS;
}
