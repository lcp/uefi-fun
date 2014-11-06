#include <efi.h>
#include <efilib.h>

VOID
efi_pause ()
{
	EFI_INPUT_KEY Key;

	WaitForSingleEvent (ST->ConIn->WaitForKey, 0);
	uefi_call_wrapper(ST->ConIn->ReadKeyStroke, 2, ST->ConIn, &Key);
}

EFI_STATUS
set_console_mode (INT32 mode)
{
	EFI_STATUS rc;
	UINTN column;
	UINTN row;

	rc = uefi_call_wrapper(ST->ConOut->QueryMode, 4, ST->ConOut, mode, &column, &row);
	if (EFI_ERROR(rc)) {
		Print (L"Mode %d col: -1, row: -1\n", mode);
		return rc;
	}

	rc = uefi_call_wrapper(ST->ConOut->SetMode, 4, ST->ConOut, mode);
	Print (L"Mode %d col: %d, row: %d\n", mode, column, row);

	return rc;
}

EFI_STATUS
efi_main (EFI_HANDLE image_handle, EFI_SYSTEM_TABLE *systab)
{
	INT32 i;

	InitializeLib(image_handle, systab);

	for (i = 0; i < ST->ConOut->Mode->MaxMode; i++) {
		set_console_mode (i);
		Print (L"\nPress any key to continue...\n");
		efi_pause ();
	}

	return EFI_SUCCESS;
}
