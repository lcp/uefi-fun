#include <efi.h>
#include <efilib.h>

#define MY_GUID { 0x7cc5ce18, 0x259b, 0x4df6, {0x8c, 0x9b, 0xa4, 0xf1, 0x50, 0xee, 0x43, 0xfa} }

EFI_STATUS
efi_main (EFI_HANDLE image, EFI_SYSTEM_TABLE *systab)
{
	EFI_GUID guid = MY_GUID;
	EFI_STATUS efi_status;
	UINT8 data[10];

	InitializeLib(image, systab);

	SetMem(data, 10, 1);

	/* Write a variable */
	efi_status = uefi_call_wrapper(RT->SetVariable, 5, L"WriteTest", &guid,
				       EFI_VARIABLE_NON_VOLATILE
				       | EFI_VARIABLE_BOOTSERVICE_ACCESS
				       | EFI_VARIABLE_APPEND_WRITE,
				       10, data);
	if (efi_status != EFI_SUCCESS) {
		Print(L"Failed to set variable %r\n", efi_status);
		return efi_status;
	}

	/* Delete a variable */
	efi_status = uefi_call_wrapper(RT->SetVariable, 5, L"WriteTest", &guid,
				       EFI_VARIABLE_NON_VOLATILE
				       | EFI_VARIABLE_BOOTSERVICE_ACCESS,
				       0, NULL);
	if (efi_status != EFI_SUCCESS) {
		Print(L"Failed to delete variable %r\n", efi_status);
		return efi_status;
	}

	Print(L"DONE\n");

	return efi_status;
}
