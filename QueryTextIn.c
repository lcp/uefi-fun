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
print_handle_devpath (EFI_HANDLE Handle)
{
	EFI_DEVICE_PATH *devpath;
	CHAR16 *path_str = NULL;

	devpath = DevicePathFromHandle (Handle);

	if (devpath) {
		path_str = DevicePathToStr (devpath);
		Print (L"%x: %s\n", Handle, path_str);
		FreePool (path_str);
	} else {
		Print (L"%x: NULL\n", Handle);
	}

	return EFI_SUCCESS;
}

EFI_STATUS
show_by_protocol (EFI_GUID *protocol)
{
	EFI_STATUS rc;
	EFI_HANDLE *Handles;
	UINTN NoHandles;
	UINTN i;

	rc = LibLocateHandle(ByProtocol, protocol, NULL, &NoHandles,
			     &Handles);
	if (EFI_ERROR(rc)) {
		Print (L"Failed to get the handle list\n");
		return rc;
	}

	for (i = 0; i < NoHandles; i++)
		print_handle_devpath (Handles[i]);

	return EFI_SUCCESS;
}

EFI_STATUS
efi_main (EFI_HANDLE image_handle, EFI_SYSTEM_TABLE *systab)
{
	EFI_STATUS rc;

	InitializeLib(image_handle, systab);

	Print (L"ConsoleInHandle: %x\n\n", ST->ConsoleInHandle);

	Print (L"Check Simple_Text_Input_Protocol\n");
	rc = show_by_protocol (&TextInProtocol);
	Print (L"Press any key to continue...\n");
	efi_pause ();

	return rc;
}
