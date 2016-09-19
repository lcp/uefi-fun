#!/usr/bin/perl

use strict;
use warnings;
use FileHandle;

sub read_file($)
{
	my ($file) = @_;
	my $contents;
	my $len;

	open(FD, "<$file") || die $file;
	binmode FD;
	my @st = stat(FD);
	die $file if (!@st);
	$len = read(FD, $contents, $st[7]) || die $file;
	close(FD) || die $file;
	die "$file: Wanted length ", $st[7], ", got ", $len, "\n"
		if ($len != $st[7]);
	return $contents;
}

if ($#ARGV != 0) {
	print "Usage: efi-header <pe-coff image>\n";
	exit;
}

my $pe_image = read_file($ARGV[0]);
my $pe_image_len = length($pe_image);
my $pe32plus = 0;

my @header_name;
my @padding;
my @format;

printf "EFI Image DOS Header\n";
my @efi_dos_header1;
my @efi_dos_header2;
my $e_lfanew;
# EFI_IMAGE_DOS_HEADER (64 bytes)
#   UINT16  e_magic;    ///< Magic number.
#   UINT16  e_cblp;     ///< Bytes on last page of file.
#   UINT16  e_cp;       ///< Pages in file.
#   UINT16  e_crlc;     ///< Relocations.
#   UINT16  e_cparhdr;  ///< Size of header in paragraphs.
#   UINT16  e_minalloc; ///< Minimum extra paragraphs needed.
#   UINT16  e_maxalloc; ///< Maximum extra paragraphs needed.
#   UINT16  e_ss;       ///< Initial (relative) SS value.
#   UINT16  e_sp;       ///< Initial SP value.
#   UINT16  e_csum;     ///< Checksum.
#   UINT16  e_ip;       ///< Initial IP value.
#   UINT16  e_cs;       ///< Initial (relative) CS value.
#   UINT16  e_lfarlc;   ///< File address of relocation table.
#   UINT16  e_ovno;     ///< Overlay number.
#   UINT16  e_res[4];   ///< Reserved words.
#   UINT16  e_oemid;    ///< OEM identifier (for e_oeminfo).
#   UINT16  e_oeminfo;  ///< OEM information; e_oemid specific.
#   UINT16  e_res2[10]; ///< Reserved words.
#   UINT32  e_lfanew;   ///< File address of new exe header.
#
my($e_magic) = unpack("v", substr($pe_image, 0, 2));
# e_magic must be 'M''Z'
die "not a EFI Image\n" unless ($e_magic == 0x5A4D);

@header_name = qw(Magic BytesOnLastPage Pages Relocations SizeOfHeader
		  MinAlloc MaxAlloc InitialSS InitialSP Checksum InitialIP
		  InitialCS RelocationTable OverlayNumber);
@padding = ("\t\t\t\t", "\t\t\t", "\t\t\t\t", "\t\t\t", "\t\t\t", "\t\t\t",
	    "\t\t\t", "\t\t\t", "\t\t\t", "\t\t\t", "\t\t\t", "\t\t\t",
	    "\t\t\t", "\t\t\t");
@format = qw(0x%0X %d %d 0x%0X %d %d %d 0x%0X 0x%0X 0x%0X 0x%0X 0x%0X 0x%0X %d);
(@efi_dos_header1) = unpack("v14", substr($pe_image, 0, 28));
for (my $i = 0; $i <= $#efi_dos_header1; $i++) {
	printf "$header_name[$i]$padding[$i]$format[$i]\n", $efi_dos_header1[$i];
}

@header_name = qw(OEM_ID OEM_INFO);
@padding = ("\t\t\t\t", "\t\t\t");
@format = qw(0x%0X 0x%0X);
(@efi_dos_header2) = unpack("v14", substr($pe_image, 36, 4));
for (my $i = 0; $i <= $#efi_dos_header2; $i++) {
	printf "$header_name[$i]$padding[$i]$format[$i]\n", $efi_dos_header2[$i];
}

($e_lfanew) = unpack("V", substr($pe_image, 60, 4));
printf "NewHeaderAddress\t\t0x%0X\n", $e_lfanew;


# Match Signature 'P''E''\0''\0'
my($Signature) = unpack("V", substr($pe_image, $e_lfanew, 4));
die "not a PE Image\n" unless ($Signature == 0x4550);

printf "\n";

printf "COFF Headers\n";
my @coff_header;
# COFF File Header (Object and Image)
#   UINT16  Machine;
#   UINT16  NumberOfSections;
#   UINT32  TimeDateStamp;
#   UINT32  PointerToSymbolTable;
#   UINT32  NumberOfSymbols;
#   UINT16  SizeOfOptionalHeader;
#   UINT16  Characteristics;
@header_name = qw(Machine NumberOfSections TimeDateStamp PointerToSymbolTable
		  NumberOfSymbols SizeOfOptionalHeader Characteristics);
@padding = ("\t\t\t\t", "\t\t", "\t\t\t", "\t\t", "\t\t\t", "\t\t", "\t\t\t");
@format = qw(0x%X %d 0x%X 0x%X %d %d 0x%X);
(@coff_header) = unpack("v2V3v2", substr($pe_image, $e_lfanew + 4, 20));
for (my $i = 0; $i <= $#coff_header; $i++) {
	printf "$header_name[$i]$padding[$i]$format[$i]\n", $coff_header[$i];
}

# Check the pe header magic
my($pe_magic) = unpack("v", substr($pe_image, $e_lfanew+24, 2));
if ($pe_magic == 0x10b) {
	$pe32plus = 0;
} elsif ($pe_magic == 0x20b) {
	$pe32plus = 1;
} else {
	die "unknown PE header\n";
}

printf "\n";

my @optional_header1;
my @optional_header2;
my $oh_offset;
if ($pe32plus == 1) {
	printf "Optional Headers for PE32+\n";
	# Optional Header Standard Fields for PE32+
	#   Standard fields
	#     UINT16  Magic;
	#     UINT8   MajorLinkerVersion;
	#     UINT8   MinorLinkerVersion;
	#     UINT32  SizeOfCode;
	#     UINT32  SizeOfInitializedData;
	#     UINT32  SizeOfUninitializedData;
	#     UINT32  AddressOfEntryPoint;
	#     UINT32  BaseOfCode;
	@header_name = qw(Magic MajorLinkerVersion MinorLinkerVersion SizeOfCode
       			  SizeOfInitializedData SizeOfUninitializedData
			  AddressOfEntryPoint BaseOfCode);
	@padding = ("\t\t\t\t", "\t\t", "\t\t", "\t\t\t", "\t\t", "\t\t", "\t\t",
		    "\t\t\t", "\t\t\t");
	@format = qw(0x%X %d %d %d %d %d 0x%X 0x%X);
	(@optional_header1) = unpack("vC2V5", substr($pe_image, $e_lfanew+24, 24));

	for (my $i = 0; $i <= $#optional_header1; $i++) {
		printf "$header_name[$i]$padding[$i]$format[$i]\n", $optional_header1[$i];
	}

	#   Optional Header Windows-Specific Fields
	#     UINT64  ImageBase;
	#     UINT32  SectionAlignment;
	#     UINT32  FileAlignment;
	#     UINT16  MajorOperatingSystemVersion;
	#     UINT16  MinorOperatingSystemVersion;
	#     UINT16  MajorImageVersion;
	#     UINT16  MinorImageVersion;
	#     UINT16  MajorSubsystemVersion;
	#     UINT16  MinorSubsystemVersion;
	#     UINT32  Win32VersionValue;
	#     UINT32  SizeOfImage;
	#     UINT32  SizeOfHeaders;
	#     UINT32  CheckSum;
	#     UINT16  Subsystem;
	#     UINT16  DllCharacteristics;
	#     UINT64  SizeOfStackReserve;
	#     UINT64  SizeOfStackCommit;
	#     UINT64  SizeOfHeapReserve;
	#     UINT64  SizeOfHeapCommit;
	#     UINT32  LoaderFlags;
	#     UINT32  NumberOfRvaAndSizes;
	@header_name = qw(ImageBase SectionAlignment FileAlignment
			  MajorOperatingSystemVersion MinorOperatingSystemVersion
			  MajorImageVersion MinorImageVersion
			  MajorSubsystemVersion MinorSubsystemVersion
			  Win32VersionValue SizeOfImage SizeOfHeaders CheckSum
			  Subsystem DllCharacteristics SizeOfStackReserve
			  SizeOfStackCommit SizeOfHeapReserve SizeOfHeapCommit
			  LoaderFlags NumberOfRvaAndSizes);
	@format = qw(0x%X 0x%X 0x%X %d %d %d %d %d %d 0x%04X %d %d 0x%X 0x%X 0x%X %d
       		     %d %d %d 0x%X %d);
	@padding = ("\t\t\t", "\t\t", "\t\t\t", "\t", "\t", "\t\t", "\t\t", "\t\t",
		    "\t\t", "\t\t", "\t\t\t", "\t\t\t", "\t\t\t", "\t\t\t", "\t\t",
		    "\t\t", "\t\t", "\t\t", "\t\t", "\t\t\t", "\t\t");
	(@optional_header2) = unpack("QV2v6V4v2Q4V2", substr($pe_image, $e_lfanew+48, 88));

	$oh_offset = 136; 
} else {
	printf "Optional Headers for PE32\n";
	# Optional Header Standard Fields for PE32
	#   Standard fields
	#     UINT16  Magic;
	#     UINT8   MajorLinkerVersion;
	#     UINT8   MinorLinkerVersion;
	#     UINT32  SizeOfCode;
	#     UINT32  SizeOfInitializedData;
	#     UINT32  SizeOfUninitializedData;
	#     UINT32  AddressOfEntryPoint;
	#     UINT32  BaseOfCode;
	#     UINT32  BaseOfData;
	@header_name = qw(Magic MajorLinkerVersion MinorLinkerVersion SizeOfCode
			  SizeOfInitializedData SizeOfUninitializedData
			  AddressOfEntryPoint BaseOfCode BaseOfData);
	@padding = ("\t\t\t\t", "\t\t", "\t\t", "\t\t\t", "\t\t", "\t\t", "\t\t",
		    "\t\t\t", "\t\t\t", "\t\t\t");
	@format = qw(0x%X %d %d %d %d %d 0x%X 0x%X 0x%X);
	(@optional_header1) = unpack("vC2V5", substr($pe_image, $e_lfanew+24, 28));

	for (my $i = 0; $i <= $#optional_header1; $i++) {
		printf "$header_name[$i]$padding[$i]$format[$i]\n", $optional_header1[$i];
	}

	#   Optional Header Windows-Specific Fields
	#     UINT32  ImageBase;
	#     UINT32  SectionAlignment;
	#     UINT32  FileAlignment;
	#     UINT16  MajorOperatingSystemVersion;
	#     UINT16  MinorOperatingSystemVersion;
	#     UINT16  MajorImageVersion;
	#     UINT16  MinorImageVersion;
	#     UINT16  MajorSubsystemVersion;
	#     UINT16  MinorSubsystemVersion;
	#     UINT32  Win32VersionValue;
	#     UINT32  SizeOfImage;
	#     UINT32  SizeOfHeaders;
	#     UINT32  CheckSum;
	#     UINT16  Subsystem;
	#     UINT16  DllCharacteristics;
	#     UINT32  SizeOfStackReserve;
	#     UINT32  SizeOfStackCommit;
	#     UINT32  SizeOfHeapReserve;
	#     UINT32  SizeOfHeapCommit;
	#     UINT32  LoaderFlags;
	#     UINT32  NumberOfRvaAndSizes;
	@header_name = qw(ImageBase SectionAlignment FileAlignment
			  MajorOperatingSystemVersion MinorOperatingSystemVersion
			  MajorImageVersion MinorImageVersion
			  MajorSubsystemVersion MinorSubsystemVersion
			  Win32VersionValue SizeOfImage SizeOfHeaders CheckSum
			  Subsystem DllCharacteristics SizeOfStackReserve
			  SizeOfStackCommit SizeOfHeapReserve SizeOfHeapCommit
			  LoaderFlags NumberOfRvaAndSizes);
	@padding = ("\t\t\t", "\t\t", "\t\t\t", "\t", "\t", "\t\t", "\t\t", "\t\t",
		    "\t\t", "\t\t", "\t\t\t", "\t\t\t", "\t\t\t", "\t\t\t", "\t\t",
		    "\t\t", "\t\t", "\t\t", "\t\t", "\t\t\t", "\t\t");
	@format = qw(0x%X 0x%X 0x%X %d %d %d %d %d %d 0x%04X %d %d 0x%X 0x%X 0x%X %d
       		     %d %d %d 0x%X %d);
	(@optional_header2) = unpack("V3v6V4v2V6", substr($pe_image, $e_lfanew+56, 68));

	$oh_offset = 124;
}

for (my $i = 0; $i <= $#optional_header2; $i++) {
	printf "$header_name[$i]$padding[$i]$format[$i]\n", $optional_header2[$i];
}

my $v_address;
my $size;
#     #define EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES 16
#     EFI_IMAGE_DATA_DIRECTORY  DataDirectory[EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES];
#       typedef struct {
#         UINT32  VirtualAddress;
#         UINT32  Size;
#       } EFI_IMAGE_DATA_DIRECTORY;
#
my $dir_offset = $e_lfanew+$oh_offset;
my @dir = qw(DIRECTORY_ENTRY_EXPORT DIRECTORY_ENTRY_IMPORT DIRECTORY_ENTRY_RESOURCE
	     DIRECTORY_ENTRY_EXCEPTION DIRECTORY_ENTRY_SECURITY DIRECTORY_ENTRY_BASERELOC
	     DIRECTORY_ENTRY_DEBUG DIRECTORY_ENTRY_COPYRIGHT DIRECTORY_ENTRY_GLOBALPTR
	     DIRECTORY_ENTRY_TLS DIRECTORY_ENTRY_LOAD_CONFIG);
for (my $i = 0; $i <= $#dir; $i++) {
	($v_address, $size) = unpack("V2", substr($pe_image, $dir_offset+$i*8, 8));
	printf "0x%016X 0x%08X   $dir[$i]\n", $v_address, $size;
}
