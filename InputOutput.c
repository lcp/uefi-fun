#include <efi.h>
#include <efilib.h>
#include "PasswordHash.h"

#define STRING_LEN 30

EFI_STATUS
efi_main (EFI_HANDLE image, EFI_SYSTEM_TABLE *systab)
{
	CHAR16 str[STRING_LEN];
	char str_a[STRING_LEN];
	int i;

	InitializeLib(image, systab);

	Input(NULL, str, STRING_LEN);

	Print(L"\n%s\n", str);

	for (i = 0; i < STRING_LEN && str[i] != L'\0'; i++)
		str_a[i] = (char)str[i];
	str_a[i] = '\0';

	Print(L"CHAR16 string to char string\n");
	Print(L"%a\n", str_a);

	Print(L"PasswordHash size: %d\n", sizeof(PASSWORD_HASH));

	return EFI_SUCCESS;
}
