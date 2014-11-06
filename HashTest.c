#include <efi.h>
#include <efilib.h>

#define EFI_HASH_SERVICE_BINDING_PROTOCOL_GUID \
    {0x42881c98, 0xa4f3, 0x44b0, {0xa3, 0x9d, 0xdf, 0xa1, 0x86, 0x67, 0xd8, 0xcd}}

#define EFI_HASH_PROTOCOL_GUID \
    {0xc5184932, 0xdba5, 0x46db, {0xa5, 0xba, 0xcc,  0xb, 0xda, 0x9c, 0x14, 0x35}}

#define EFI_HASH_ALGORITHM_SHA1_GUID \
    {0x2ae9d80f, 0x3fb2, 0x4095, {0xb7, 0xb1, 0xe9, 0x31, 0x57, 0xb9, 0x46, 0xb6}} 
#define EFI_HASH_ALGORITHM_SHA224_GUID \
    {0x8df01a06, 0x9bd5, 0x4bf7, {0xb0, 0x21, 0xdb, 0x4f, 0xd9, 0xcc, 0xf4, 0x5b}}
#define EFI_HASH_ALGORITHM_SHA256_GUID \
    {0x51aa59de, 0xfdf2, 0x4ea3, {0xbc, 0x63, 0x87, 0x5f, 0xb7, 0x84, 0x2e, 0xe9}} 
#define EFI_HASH_ALGORITHM_SHA384_GUID \
    {0xefa96432, 0xde33, 0x4dd2, {0xae, 0xe6, 0x32, 0x8c, 0x33, 0xdf, 0x77, 0x7a}}
#define EFI_HASH_ALGORITHM_SHA512_GUID \
    {0xcaa4381e, 0x750c, 0x4770, {0xb8, 0x70, 0x7a, 0x23, 0xb4, 0xe4, 0x21, 0x30}} 
#define EFI_HASH_ALGORTIHM_MD5_GUID \
    {0xaf7c79c,  0x65b5, 0x4319, {0xb0, 0xae, 0x44, 0xec, 0x48, 0x4e, 0x4a, 0xd7}}
#define EFI_HASH_ALGORITHM_SHA1_NOPAD_GUID \
    {0x24c5dc2f, 0x53e2, 0x40ca, {0x9e, 0xd6, 0xa5, 0xd9, 0xa4, 0x9f, 0x46, 0x3b}} 
#define EFI_HASH_ALGORITHM_SHA256_NOPAD_GUID \
    {0x8628752a, 0x6cb7, 0x4814, {0x96, 0xfc, 0x24, 0xa8, 0x15, 0xac, 0x22, 0x26}} 

typedef UINT8 EFI_MD5_HASH[16];
typedef UINT8 EFI_SHA1_HASH[20];
typedef UINT8 EFI_SHA224_HASH[28];
typedef UINT8 EFI_SHA256_HASH[32];
typedef UINT8 EFI_SHA384_HASH[48];
typedef UINT8 EFI_SHA512_HASH[64];
typedef union _EFI_HASH_OUTPUT {
	EFI_MD5_HASH    *Md5Hash;
	EFI_SHA1_HASH   *Sha1Hash;
	EFI_SHA224_HASH *Sha224Hash;
	EFI_SHA256_HASH *Sha256Hash;
	EFI_SHA384_HASH *Sha384Hash;
	EFI_SHA512_HASH *Sha512Hash;
} EFI_HASH_OUTPUT;

INTERFACE_DECL(_EFI_HASH);

typedef
EFI_STATUS
(EFIAPI *EFI_HASH_GET_HASH_SIZE) (
	IN struct _EFI_HASH *This,
	IN EFI_GUID         *HashAlgorithm,
	OUT UINTN            HashSize
	);

typedef
EFI_STATUS
(EFIAPI *EFI_HASH_HASH) (
	IN struct _EFI_HASH *This,
	IN EFI_GUID         *HashAlgorithm,
	IN BOOLEAN           Extend,
	IN UINT8            *Message,
	IN UINT64            MessageSize,
	IN OUT EFI_HASH_OUTPUT       *Hash
	);

typedef struct _EFI_HASH_PROTOCOL {
	EFI_HASH_GET_HASH_SIZE GetHashSize;
	EFI_HASH_HASH          Hash;
} EFI_HASH;

EFI_STATUS
hash_sha512 (void *in, UINT64 len, EFI_HASH_OUTPUT *hash)
{
	EFI_STATUS status;
	EFI_GUID HashProtocol = EFI_HASH_PROTOCOL_GUID;
	EFI_GUID AlgoSha512 = EFI_HASH_ALGORITHM_SHA512_GUID;
	EFI_HASH *hash_handle;

	/* FIXME HashProtocol cannot be located by LocateProtocol */
	status = LibLocateProtocol(&HashProtocol, (VOID *)&hash_handle);
	if (EFI_ERROR(status))
		return status;

	status = uefi_call_wrapper(hash_handle->Hash, 6, hash_handle,
				   &AlgoSha512, FALSE, in, len, hash);

	return status;
}

EFI_STATUS
bind_hash_service (EFI_SERVICE_BINDING *hash_binding, EFI_HASH *hash_handle)
{
	EFI_STATUS status;
	EFI_GUID HashBinding = EFI_HASH_SERVICE_BINDING_PROTOCOL_GUID;
	UINTN NoHandles;
	EFI_HANDLE *hash_binding_handle;

	status = uefi_call_wrapper(BS->LocateHandleBuffer, 5, ByProtocol,
				   &HashBinding, NULL, &NoHandles, &hash_binding_handle);
	if (EFI_ERROR(status))
		return status;

	/* TODO EFI_HASH_SERVICE_BINDING_PROTOCOL.CreateChild() */

	return EFI_SUCCESS;
}

EFI_STATUS
efi_main (EFI_HANDLE image, EFI_SYSTEM_TABLE *systab)
{
	EFI_STATUS status;
	EFI_SERVICE_BINDING *hash_binding = NULL;
	EFI_HASH *hash_handle;
	EFI_HASH_OUTPUT hash;
	EFI_SHA512_HASH *sha512_hash;
	CHAR16 str[] = L"Just a test";
	UINT64 str_len;
	int i;

	InitializeLib(image, systab);

	str_len = StrSize(str);

	status = bind_hash_service(hash_binding, hash_handle);
	if (EFI_ERROR(status)) {
		Print(L"bind_hash_service %r\n", status);
		return status;
	}

	status = hash_sha512(str, str_len, &hash);
	if (EFI_ERROR(status)) {
		Print(L"sha512 %r\n", status);
		return status;
	}

	Print(L"Print hash\n");
	sha512_hash = hash.Sha512Hash;
	for (i = 0; i < 64; i++) {
		Print(L"%X", sha512_hash[i]);
	}
	Print(L"\n");

	return EFI_SUCCESS;
}
