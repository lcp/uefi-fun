#!/usr/bin/perl

=head1 efiversion.pl

efiversion.pl - show or modify the version fields in the EFI image

=head1 SYNOPSIS

efiversion.pl [OPTIONS] FILE

=head1 OPTIONS

=over 4

=item B<--major-os=NUMBER>

assign the major OS version

=item B<--minor-os=NUMBER>

assign the minor OS version

=item B<--major-image=NUMBER>

assign the major image version

=item B<--minor-image=NUMBER>

assign the minor image version

=item B<--major-subsys=NUMBER>

assign the major subsystem version

=item B<--minor-subsys=NUMBER>

assign the minor subsystem version

=item B<--help, -h>

print help

=back

=head1 DESCRIPTION

A script to modify the version fields in the header of the EFI image

Show the versions:
$ efiversion.pl sample.efi

Modify the versions:
$ efiversion.pl --major-os=1 --minor-os=2 sample.efi

=cut

use strict;
use warnings;
use FileHandle;
use Getopt::Long;
Getopt::Long::Configure("no_ignore_case");

my %options;

sub usage($) {
	my $r = shift;
	eval "use Pod::Usage; pod2usage($r);";
	if ($@) {
		die "cannot display help, install perl(Pod::Usage)\n";
	}
}

my $options;
my $major_os = '';
my $minor_os = '';
my $major_image = '';
my $minor_image = '';
my $major_subsys = '';
my $minor_subsys = '';
my $help = '';
my $overwrite = '';

GetOptions(
	"major-os=o" => \$major_os,
	"minor-os=o" => \$minor_os,
	"major-image=o" => \$major_image,
	"minor-image=o" => \$minor_image,
	"major-subsys=o" => \$major_subsys,
	"minor-subsys=o" => \$minor_subsys,
	"help|h" => \$help,
) or usage(1);

usage(1) unless @ARGV;
usage(0) if ($help);

sub not_ushort($)
{
	my ($number) = @_;

	return 0 unless $number;
	return 1 if ($number < 0 or $number > 0xFFFF);

	$overwrite = "y";

	return 0;
}

sub check_args
{
	return 0 if not_ushort($major_os);
	return 0 if not_ushort($minor_os);
	return 0 if not_ushort($major_image);
	return 0 if not_ushort($minor_image);
	return 0 if not_ushort($major_subsys);
	return 0 if not_ushort($minor_subsys);
	return 1;
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

sub get_signature_offset($)
{
	my ($image) = @_;

	# e_magic must be 'M''Z'
	my ($e_magic) = unpack("n", substr($image, 0, 2));
	die "not a EFI Image\n" unless ($e_magic == 0x4D5A);

	# Get the offset to the PE signature
	my ($e_lfanew) = unpack("V", substr($image, 0x3C, 4));

	# Match Signature 'P''E''\0''\0'
	my ($Signature) = unpack("N", substr($image, $e_lfanew, 4));
	die "not a PE Image\n" unless ($Signature == 0x50450000);

	return $e_lfanew;
}

sub write_file($)
{
	my ($file, $contents) = @_;

	open(FD, ">$file") || die $file;
	binmode FD;
	print FD $contents;
	close(FD) || die $file;
}

sub set_version($)
{
	my ($image_ptr, $offset, $value) = @_;
	my $packed = pack("v", $value);
	substr($$image_ptr, $offset, 2, $packed);
}

die "invalid arguments\n" unless check_args;

my ($file) = @ARGV;
my $pe_image = read_file($file) if ($file);
my $e_lfanew = get_signature_offset($pe_image);

# [PE Signature][COFF File Header][Optional Header]
#     4 bytes        20 bytes
#
# The offset of MajorOperatingSystemVersion in the Optional Header: 40
#
# The file offset of MajorOperatingSystemVersion: $e_lfanew + 24 + 40
#
# Our targets:
#   UINT16  MajorOperatingSystemVersion;
#   UINT16  MinorOperatingSystemVersion;
#   UINT16  MajorImageVersion;
#   UINT16  MinorImageVersion;
#   UINT16  MajorSubsystemVersion;
#   UINT16  MinorSubsystemVersion;
my $os_offset = $e_lfanew + 64;

if ($overwrite) {
	# Write the file
	&set_version(\$pe_image, $os_offset,      $major_os)     if ($major_os);
	&set_version(\$pe_image, $os_offset + 2,  $minor_os)     if ($minor_os);
	&set_version(\$pe_image, $os_offset + 4,  $major_image)  if ($major_image);
	&set_version(\$pe_image, $os_offset + 6,  $minor_image)  if ($minor_image);
	&set_version(\$pe_image, $os_offset + 8,  $major_subsys) if ($major_subsys);
	&set_version(\$pe_image, $os_offset + 10, $minor_subsys) if ($minor_subsys);
	&write_file($file, $pe_image);
} else {
	# Get the versions
	(my @versions) = unpack("v6", substr($pe_image, $os_offset, 12));

	printf "MajorOperatingSystemVersion\t0x%X\n", $versions[0];
	printf "MinorOperatingSystemVersion\t0x%X\n", $versions[1];
	printf "MajorImageVersion\t\t0x%X\n",         $versions[2];
	printf "MinorImageVersion\t\t0x%X\n",         $versions[3];
	printf "MajorSubSystemVersion\t\t0x%X\n",     $versions[4];
	printf "MajorSubSystemVersion\t\t0x%X\n",     $versions[5];
}
