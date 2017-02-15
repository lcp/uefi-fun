#!/usr/bin/perl

=head1 svheader.pl

svheader.pl - show or modify the Security version fields for Linux kernel

=head1 SYNOPSIS

svheader.pl [OPTIONS] FILE

=head1 OPTIONS

=over 4

=item B<--signer=STRING>

assign the signer name (4 characters)

=item B<--dv=NUMBER>

assign the distro version

=item B<--sv=NUMBER>

assign the security version

=item B<--output=FILE, -o FILE>

write the result to the file

=item B<--help, -h>

print help

=back

=head1 DESCRIPTION

A script to modify the Security version fields for Linux kernel

Show the versions:
$ svheader.pl sample.efi

Modify the versions:
$ svheader.pl --signer="SUSE" --dv=1203 --sv=1 -o out.efi sample.efi

=cut

use strict;
use warnings;
use FileHandle;
use Getopt::Long;
Getopt::Long::Configure("no_ignore_case");

sub usage($) {
	my $r = shift;
	eval "use Pod::Usage; pod2usage($r);";
	if ($@) {
		die "cannot display help, install perl(Pod::Usage)\n";
	}
}

my $signer = '';
my $dv = '';
my $sv = '';
my $output = '';
my $help = '';

GetOptions(
	"signer=s" => \$signer,
	"dv=o" => \$dv,
	"sv=o" => \$sv,
	"output=s" => \$output,
	"help|h" => \$help,
) or usage(1);

usage(1) unless @ARGV;
usage(0) if ($help);

sub check_args
{
	if (length($output) == 0) {
		return;
	}

	die "Signer not specified\n" if !$signer;
	die "Distro version not specified\n" if !$dv;
	die "Security version not specified\n" if !$sv;

	die "Signer has to be a 4 character string\n" if length($signer) != 4;
	die "invalid distro version\n" if $dv < 0 or $dv > 0xFFFF;
	die "invalid security version\n" if $sv < 0 or $sv > 0xFFFF;
}

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

sub find_header_address($)
{
	my ($image) = @_;

	# e_magic must be 'M''Z'
	my ($e_magic) = unpack("n", substr($image, 0, 2));
	die "not a EFI Image\n" unless ($e_magic == 0x4D5A);

	my ($e_lfanew) = unpack("V", substr($image, 60, 4));

	# Match Signature 'P''E''\0''\0'
	my ($Signature) = unpack("N", substr($image, $e_lfanew, 4));
	die "not a PE Image\n" unless ($Signature == 0x50450000);

	return $e_lfanew;
}

sub set_signer($)
{
	my ($image_ptr, $offset, $value) = @_;
	my $packed = pack("A4", $value);
	substr($$image_ptr, $offset, 4, $packed);
}

sub set_version($)
{
	my ($image_ptr, $offset, $value) = @_;
	my $packed = pack("v", $value);
	substr($$image_ptr, $offset, 2, $packed);
}

sub write_file($)
{
	my ($file, $contents) = @_;

	open(FD, ">$file") || die $file;
	binmode FD;
	print FD $contents;
	close(FD) || die $file;
}

check_args;

my ($file) = @ARGV;
my $pe_image = read_file($file) if ($file);
my $e_lfanew = find_header_address($pe_image);

# The file offset of the Optional Header: $e_lfanew + 24
#
# Optional Header for PE32+
#   UINT16  Magic;
#   UINT8   MajorLinkerVersion;
#   UINT8   MinorLinkerVersion;
#   UINT32  SizeOfCode;
#   UINT32  SizeOfInitializedData;
#   UINT32  SizeOfUninitializedData;
#   UINT32  AddressOfEntryPoint;
#   UINT32  BaseOfCode;
#   UINT64  ImageBase;
#   UINT32  SectionAlignment;
#   UINT32  FileAlignment;
#
# -- 40 bytes --
#
#   UINT16  MajorOperatingSystemVersion;
#   UINT16  MinorOperatingSystemVersion;
#   UINT16  MajorImageVersion;
#   UINT16  MinorImageVersion;
#
# Optional Header for PE32
#   UINT16  Magic;
#   UINT8   MajorLinkerVersion;
#   UINT8   MinorLinkerVersion;
#   UINT32  SizeOfCode;
#   UINT32  SizeOfInitializedData;
#   UINT32  SizeOfUninitializedData;
#   UINT32  AddressOfEntryPoint;
#   UINT32  BaseOfCode;
#   UINT32  BaseOfData;
#   UINT32  ImageBase;
#   UINT32  SectionAlignment;
#   UINT32  FileAlignment;
#
# -- 40 bytes -- 
#
#   UINT16  MajorOperatingSystemVersion;
#   UINT16  MinorOperatingSystemVersion;
#   UINT16  MajorImageVersion;
#   UINT16  MinorImageVersion;
my $os_offset = $e_lfanew + 24 + 40;
my $image_offset = $os_offset+4;

if ($output) {
	# Write the file
	&set_signer(\$pe_image, $os_offset, $signer) if ($signer);
	&set_version(\$pe_image, $image_offset, $dv) if ($dv);
	&set_version(\$pe_image, $image_offset+2, $sv) if ($sv);
	&write_file($output, $pe_image);
} else {
	# Get the versions
	($signer) = unpack("A4", substr($pe_image, $os_offset, 4));
	($dv, $sv) = unpack("v2", substr($pe_image, $image_offset, 4));

	printf "Signer\t\t%s\n", $signer;
	printf "Distro Ver.\t%d\n", $dv;
	printf "Security Ver.\t%d\n", $sv;
}
