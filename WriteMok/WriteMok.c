/* Write MokList Test */

#include <efi.h>
#include <efilib.h>

EFI_GUID SHIM_LOCK_GUID = {0x605dab50, 0xe046, 0x4300, {0xab, 0xb6, 0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23 } };

unsigned char ca_list_bin[] = {
  0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a, 0x87, 0xb5, 0xab, 0x15,
  0x5c, 0x2b, 0xf0, 0x72, 0x09, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xed, 0x03, 0x00, 0x00, 0x8f, 0xe4, 0xe9, 0xad, 0xb8, 0x9c, 0xe6, 0x98,
  0x31, 0xaf, 0xb4, 0xe6, 0x00, 0x9e, 0x2f, 0xe3, 0x30, 0x82, 0x03, 0xd9,
  0x30, 0x82, 0x02, 0xc1, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x09, 0x00,
  0x9f, 0x29, 0x3d, 0x2a, 0xff, 0x4e, 0x55, 0xcc, 0x30, 0x0d, 0x06, 0x09,
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30,
  0x81, 0x82, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
  0x02, 0x54, 0x57, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x08,
  0x0c, 0x06, 0x54, 0x61, 0x69, 0x70, 0x65, 0x69, 0x31, 0x0f, 0x30, 0x0d,
  0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x06, 0x54, 0x61, 0x69, 0x70, 0x65,
  0x69, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x09,
  0x4a, 0x75, 0x73, 0x74, 0x61, 0x74, 0x65, 0x73, 0x74, 0x31, 0x0d, 0x30,
  0x0b, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x04, 0x74, 0x65, 0x73, 0x74,
  0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x07, 0x54,
  0x65, 0x73, 0x74, 0x69, 0x6e, 0x67, 0x31, 0x1c, 0x30, 0x1a, 0x06, 0x09,
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x0d, 0x68,
  0x74, 0x74, 0x70, 0x73, 0x40, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x6d, 0x65,
  0x30, 0x1e, 0x17, 0x0d, 0x31, 0x37, 0x30, 0x32, 0x32, 0x30, 0x30, 0x36,
  0x35, 0x39, 0x31, 0x36, 0x5a, 0x17, 0x0d, 0x31, 0x38, 0x30, 0x32, 0x32,
  0x30, 0x30, 0x36, 0x35, 0x39, 0x31, 0x36, 0x5a, 0x30, 0x81, 0x82, 0x31,
  0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x54, 0x57,
  0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x06, 0x54,
  0x61, 0x69, 0x70, 0x65, 0x69, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55,
  0x04, 0x07, 0x0c, 0x06, 0x54, 0x61, 0x69, 0x70, 0x65, 0x69, 0x31, 0x12,
  0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x09, 0x4a, 0x75, 0x73,
  0x74, 0x61, 0x74, 0x65, 0x73, 0x74, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03,
  0x55, 0x04, 0x0b, 0x0c, 0x04, 0x74, 0x65, 0x73, 0x74, 0x31, 0x10, 0x30,
  0x0e, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x07, 0x54, 0x65, 0x73, 0x74,
  0x69, 0x6e, 0x67, 0x31, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48,
  0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x0d, 0x68, 0x74, 0x74, 0x70,
  0x73, 0x40, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x6d, 0x65, 0x30, 0x82, 0x01,
  0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
  0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01,
  0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xcc, 0x0b, 0xad, 0xbe, 0xbb, 0xed,
  0x37, 0x4e, 0xa4, 0xf1, 0x3e, 0xee, 0x88, 0xb4, 0x01, 0x75, 0x6e, 0x6f,
  0x67, 0x73, 0xaf, 0x9e, 0xc6, 0xaf, 0x38, 0x32, 0x55, 0xe9, 0xbe, 0x28,
  0xdd, 0x97, 0x56, 0x75, 0xbb, 0x71, 0x1b, 0xb9, 0x2c, 0x7b, 0x5b, 0x0a,
  0x60, 0xb4, 0x71, 0x79, 0x3d, 0x1c, 0xac, 0x39, 0xc7, 0xf4, 0xa4, 0x7a,
  0x69, 0x44, 0xfa, 0x56, 0x4a, 0x40, 0xf1, 0x87, 0x89, 0x8f, 0x4e, 0x1e,
  0x45, 0xaf, 0x92, 0x32, 0x7b, 0x4f, 0xfe, 0x47, 0x2d, 0x7d, 0x82, 0x5b,
  0x6c, 0xf9, 0x7e, 0xfa, 0xec, 0xd4, 0x27, 0xc1, 0x85, 0x24, 0x1d, 0x3a,
  0xe3, 0x26, 0x4e, 0x2e, 0xfc, 0x1a, 0x2f, 0xe3, 0xe4, 0xac, 0x59, 0xd2,
  0x89, 0x46, 0x52, 0x51, 0x63, 0x5c, 0xd0, 0xec, 0xd8, 0xda, 0xd3, 0x1e,
  0xfc, 0x0e, 0x91, 0xdc, 0xd5, 0x4d, 0xf1, 0xb5, 0x33, 0x0c, 0xec, 0xbe,
  0x96, 0x28, 0x5c, 0xff, 0xc0, 0x44, 0xbf, 0x2e, 0xc3, 0xf6, 0x94, 0x24,
  0x36, 0xe1, 0xd6, 0x92, 0x1f, 0xca, 0x1a, 0xe1, 0xa4, 0xef, 0x8a, 0x7b,
  0x5b, 0x6d, 0x36, 0x7a, 0x35, 0x99, 0xba, 0xae, 0xec, 0x46, 0xaf, 0xc6,
  0x97, 0xeb, 0x1e, 0x2f, 0xef, 0xf6, 0x99, 0x0a, 0x8b, 0xcb, 0x11, 0x87,
  0xdf, 0x6c, 0x6d, 0x01, 0x38, 0xad, 0xf2, 0x47, 0xf1, 0x16, 0xd4, 0xfd,
  0x82, 0x36, 0x7e, 0x4a, 0x60, 0x73, 0x3d, 0x2c, 0x98, 0xe8, 0x7a, 0x82,
  0x69, 0x91, 0xe9, 0x8b, 0xa7, 0xa2, 0xc1, 0x2d, 0xdb, 0xbb, 0xb1, 0x30,
  0x64, 0x7d, 0x07, 0xbe, 0xa4, 0xcb, 0xfe, 0x57, 0x7e, 0x5d, 0x48, 0xf1,
  0x43, 0x00, 0x8b, 0x32, 0xe0, 0x89, 0xcf, 0x82, 0xe3, 0xee, 0x6b, 0x41,
  0xd1, 0xd9, 0x5d, 0x4b, 0x8c, 0xdb, 0xac, 0x04, 0xf1, 0x46, 0xaf, 0xeb,
  0x38, 0x35, 0x55, 0x65, 0xeb, 0x48, 0x38, 0x7e, 0x75, 0xe9, 0x02, 0x03,
  0x01, 0x00, 0x01, 0xa3, 0x50, 0x30, 0x4e, 0x30, 0x1d, 0x06, 0x03, 0x55,
  0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xf3, 0x4e, 0x69, 0xdc, 0x95, 0xfe,
  0xcc, 0x4c, 0x66, 0x10, 0xb8, 0xa2, 0xfc, 0x6f, 0xf6, 0x9a, 0x48, 0xc9,
  0x10, 0x62, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30,
  0x16, 0x80, 0x14, 0xf3, 0x4e, 0x69, 0xdc, 0x95, 0xfe, 0xcc, 0x4c, 0x66,
  0x10, 0xb8, 0xa2, 0xfc, 0x6f, 0xf6, 0x9a, 0x48, 0xc9, 0x10, 0x62, 0x30,
  0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01,
  0xff, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
  0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x4a, 0x44, 0x91,
  0x1b, 0xa5, 0x33, 0x8e, 0xa0, 0x45, 0x99, 0x41, 0x92, 0x31, 0x20, 0x2a,
  0x6d, 0x85, 0x76, 0xfe, 0x31, 0xa9, 0x43, 0x7f, 0x93, 0xd7, 0xb5, 0x30,
  0xe9, 0x8a, 0xf0, 0x94, 0xd5, 0xcd, 0xda, 0x7b, 0x99, 0x25, 0x29, 0xee,
  0x89, 0x3c, 0x20, 0xc1, 0xd1, 0x2d, 0xa4, 0x9a, 0x0f, 0xf1, 0x1d, 0xc1,
  0x95, 0x26, 0x6d, 0xe5, 0x0f, 0x17, 0x1b, 0x9a, 0x9b, 0x83, 0xf9, 0x3b,
  0x23, 0x74, 0x5f, 0xa9, 0x1a, 0xd6, 0x59, 0x51, 0x1a, 0xe4, 0x2b, 0x27,
  0xd2, 0x16, 0x8a, 0x8b, 0x86, 0x4f, 0xc5, 0xb5, 0x3b, 0xad, 0xd5, 0x61,
  0xb8, 0xbc, 0xdc, 0xee, 0x6b, 0x6b, 0x13, 0xcf, 0xde, 0xa9, 0xfc, 0xf9,
  0x75, 0x2d, 0xf4, 0x31, 0x17, 0xac, 0xf6, 0x63, 0xee, 0xae, 0x6b, 0xb2,
  0xa3, 0xb6, 0x66, 0x9b, 0xe7, 0xf2, 0x49, 0x92, 0xb4, 0x01, 0x53, 0x70,
  0x1f, 0x29, 0x37, 0xaa, 0x50, 0xc8, 0xd4, 0x74, 0xe0, 0x78, 0xb7, 0x18,
  0xae, 0xa7, 0xb2, 0x62, 0xc6, 0xf2, 0xb1, 0xaa, 0xac, 0xf5, 0x1e, 0xb3,
  0x6c, 0x16, 0xd4, 0x0e, 0x10, 0x06, 0x1f, 0x4b, 0xc2, 0xe6, 0x0c, 0xfd,
  0x05, 0xbc, 0xc1, 0xa4, 0xcb, 0xc1, 0xa9, 0x28, 0xb1, 0x35, 0xe8, 0x72,
  0xa8, 0x04, 0xfc, 0xe8, 0xfd, 0xf4, 0xff, 0x1a, 0xb2, 0xb3, 0xc3, 0xe5,
  0xed, 0xc3, 0xa9, 0x1b, 0xc9, 0xcc, 0xdb, 0x27, 0x24, 0x4c, 0x66, 0xef,
  0x7e, 0x81, 0x54, 0x46, 0x27, 0x48, 0xf1, 0xcd, 0xdf, 0xbe, 0x8c, 0x05,
  0x26, 0xb9, 0xc4, 0x0f, 0x6e, 0x86, 0x4c, 0xde, 0x1c, 0xcd, 0x84, 0x92,
  0x89, 0xfc, 0x51, 0x2f, 0x6f, 0x66, 0x56, 0x4b, 0x22, 0xaf, 0x90, 0x7e,
  0xd3, 0x88, 0x24, 0x8c, 0x5c, 0xc2, 0x35, 0x87, 0xb8, 0xe2, 0xc7, 0xfd,
  0xa8, 0x26, 0x3b, 0x90, 0x49, 0x77, 0x74, 0x91, 0x58, 0x1b, 0xcb, 0x31,
  0x29
};
unsigned int ca_list_bin_len = 1033;

static EFI_STATUS
console_get_keystroke(EFI_INPUT_KEY *key)
{
	UINTN EventIndex;
	EFI_STATUS status;

	do {
		uefi_call_wrapper(BS->WaitForEvent, 3, 1,
			          &ST->ConIn->WaitForKey, &EventIndex);
		status = uefi_call_wrapper(ST->ConIn->ReadKeyStroke, 2,
					   ST->ConIn, key);
	} while (status == EFI_NOT_READY);

	return status;
}


static VOID
console_notify(CHAR16 *line)
{
	EFI_INPUT_KEY key;

	Print(line);

	Print(L"Press any key to continue\n");
	console_get_keystroke(&key);
}

static EFI_STATUS
get_variable_attr(CHAR16 *var, UINT8 **data, UINTN *len, EFI_GUID owner,
		  UINT32 *attributes)
{
	EFI_STATUS efi_status;

	*len = 0;

	efi_status = uefi_call_wrapper(RT->GetVariable, 5, var, &owner,
				       NULL, len, NULL);
	if (efi_status != EFI_BUFFER_TOO_SMALL)
		return efi_status;

	*data = AllocateZeroPool(*len);
	if (!*data)
		return EFI_OUT_OF_RESOURCES;
	
	efi_status = uefi_call_wrapper(RT->GetVariable, 5, var, &owner,
				       attributes, len, *data);

	if (efi_status != EFI_SUCCESS) {
		FreePool(*data);
		*data = NULL;
	}
	return efi_status;
}

static EFI_STATUS write_db (CHAR16 *db_name, void *MokNew, UINTN MokNewSize)
{
	EFI_GUID shim_lock_guid = SHIM_LOCK_GUID;
	EFI_STATUS status;
	UINT32 attributes;
	void *old_data = NULL;
	void *new_data = NULL;
	UINTN old_size;
	UINTN new_size;

	status = uefi_call_wrapper(RT->SetVariable, 5, db_name,
				   &shim_lock_guid,
				   EFI_VARIABLE_NON_VOLATILE
				   | EFI_VARIABLE_BOOTSERVICE_ACCESS
				   | EFI_VARIABLE_APPEND_WRITE,
				   MokNewSize, MokNew);
	if (status == EFI_SUCCESS || status != EFI_INVALID_PARAMETER) {
		return status;
	}

	status = get_variable_attr(db_name, (UINT8 **)&old_data, &old_size,
				   shim_lock_guid, &attributes);
	if (EFI_ERROR(status) && status != EFI_NOT_FOUND) {
		return status;
	}

	/* Check if the old db is compromised or not */
	if (attributes & EFI_VARIABLE_RUNTIME_ACCESS) {
		FreePool(old_data);
		old_data = NULL;
		old_size = 0;
	}

	new_size = old_size + MokNewSize;
	new_data = AllocatePool(new_size);
	if (new_data == NULL) {
		status = EFI_OUT_OF_RESOURCES;
		goto out;
	}

	CopyMem(new_data, old_data, old_size);
	CopyMem(new_data + old_size, MokNew, MokNewSize);

	status = uefi_call_wrapper(RT->SetVariable, 5, db_name,
				   &shim_lock_guid,
				   EFI_VARIABLE_NON_VOLATILE
				   | EFI_VARIABLE_BOOTSERVICE_ACCESS,
				   new_size, new_data);

out:
	if (old_size > 0) {
		FreePool(old_data);
	}

	if (new_data != NULL) {
		FreePool(new_data);
	}

	return status;
}

static INTN reset_system ()
{
	uefi_call_wrapper(RT->ResetSystem, 4, EfiResetWarm,
			  EFI_SUCCESS, 0, NULL);
	console_notify(L"Failed to reboot\n");
	return -1;
}

static VOID set_moklist()
{
	EFI_INPUT_KEY key;
	EFI_STATUS status;

	Print(L"Press 'y' to set MokList\n");
	status = console_get_keystroke(&key);
	if (key.UnicodeChar != 'y') {
		return;
	}

	status = write_db(L"MokList", ca_list_bin, ca_list_bin_len);
	if (EFI_ERROR(status)) {
		console_notify(L"Failed to write MokList\n");
		return;
	}

	console_notify(L"\nReady to reset the system\n");
	reset_system();
}

static EFI_STATUS read_moklist()
{
	EFI_GUID shim_lock_guid = SHIM_LOCK_GUID;
	EFI_STATUS status;
	EFI_INPUT_KEY key;
	UINT32 attributes;
	void *data = NULL;
	UINTN size;

	status = get_variable_attr(L"MokList", (UINT8 **)&data, &size,
				   shim_lock_guid, &attributes);
	if (status == EFI_NOT_FOUND) {
		Print(L"MokList doesn't exist.\n");
		return EFI_NOT_FOUND;
	} else if (EFI_ERROR(status)) {
		Print(L"GetVariable error: %r\n", status);
		console_notify(L"Something was wrong\n");
		return status;
	}

	Print(L"MokList exists, size=%d\n", size);
	Print(L"Press 'y' to delete MokList\n");
	status = console_get_keystroke(&key);
	if (key.UnicodeChar == 'y') {
		/* Delete MokList */
		status = uefi_call_wrapper(RT->SetVariable, 5, L"MokList",
					   &shim_lock_guid,
					   EFI_VARIABLE_NON_VOLATILE
					   | EFI_VARIABLE_BOOTSERVICE_ACCESS,
					   0, NULL);
		if (EFI_ERROR(status)) {
			console_notify(L"Failed to delete MokList\n");
			goto out;
		}
		console_notify(L"\nMokList is deleted.\n");
	}
out:
	FreePool(data);
	return status;
}

EFI_STATUS efi_main(EFI_HANDLE image_handle, EFI_SYSTEM_TABLE * systab)
{
	InitializeLib(image_handle, systab);

	if (read_moklist() == EFI_NOT_FOUND) {
		set_moklist();
	}

	return EFI_SUCCESS;
}