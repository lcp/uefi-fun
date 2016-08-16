#!/usr/bin/perl

=head1 efiversion.pl

efiversion.pl - modify the version fields in the EFI image

=head1 SYNOPSIS

efiversion.pl [OPTIONS] -i input.efi -o output.efi

=head1 OPTIONS

=over 4

=item B<--major-os-version=NUMBER>

assign the major OS version

=item B<--minor-os-version=NUMBER>

assign the minor OS version

=item B<--major-image-version=NUMBER>

assign the major image version

=item B<--minor-image-version=NUMBER>

assign the minor image version

=item B<--major-subsys-version=NUMBER>

assign the major subsystem version

=item B<--minor-subsys-version=NUMBER>

assign the minor subsystem version

=item B<--input=FILE, -i FILE>

the input file

=item B<--output=FILE, -o FILE>

the output file

=item B<--help, -h>

print help

=back

=head1 DESCRIPTION

A script to modify the version fields in the header of the EFI image

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

my $major_os = '';
my $minor_os = '';
my $major_image = '';
my $minor_image = '';
my $major_subsys = '';
my $minor_subsys = '';
my $input = '';
my $output = '';
my $help = '';

GetOptions(
	"major-os-version=i" => \$major_os,
	"minor-os-version=i" => \$minor_os,
	"major-image-version=i" => \$major_image,
	"minor-image-version=i" => \$minor_image,
	"major-subsys-version=i" => \$major_subsys,
	"minor-subsys-version=i" => \$minor_subsys,
	"input=s" => \$input,
	"output=s" => \$output,
	"help|h" => \$help,
) or usage(1);

usage(1) if ($help);

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

sub write_file($)
{
	my ($file, $contents) = @_;

	open(FD, ">$file") || die $file;
	binmode FD;
	print FD $contents;
	close(FD) || die $file;
}

my $pe_image;

if ($input) {
	$pe_image = read_file($input);
} else {
	usage(1);
}

# e_magic must be 'M''Z'
my($e_magic) = unpack("v", substr($pe_image, 0, 2));
die "not a EFI Image\n" unless ($e_magic == 0x5A4D);

my($e_lfanew) = unpack("V", substr($pe_image, 60, 4));

# Match Signature 'P''E''\0''\0'
my($Signature) = unpack("V", substr($pe_image, $e_lfanew, 4));
die "not a PE Image\n" unless ($Signature == 0x4550);

my $os_offset = $e_lfanew+64;
my $image_offset = $e_lfanew+68;
my $subsys_offset = $e_lfanew+72;

if ($output) {
	# Write the file
	if ($major_os) {
		my $packed = pack("v", $major_os);
		substr($pe_image, $os_offset, 2, $packed);
	}
	if ($minor_os) {
		my $packed = pack("v", $minor_os);
		substr($pe_image, $os_offset+2, 2, $packed);
	}
	if ($major_image) {
		my $packed = pack("v", $major_image);
		substr($pe_image, $image_offset, 2, $packed);
	}
	if ($minor_image) {
		my $packed = pack("v", $minor_image);
		substr($pe_image, $image_offset+2, 2, $packed);
	}
	if ($major_subsys) {
		my $packed = pack("v", $major_subsys);
		substr($pe_image, $subsys_offset, 2, $packed);
	}
	if ($minor_subsys) {
		my $packed = pack("v", $minor_subsys);
		substr($pe_image, $subsys_offset+2, 2, $packed);
	}
	&write_file($output, $pe_image);
} else {
	# Get the versions
	my($major_os, $minor_os) = unpack("v2", substr($pe_image, $os_offset, 4));
	my($major_image, $minor_image) = unpack("v2", substr($pe_image, $image_offset, 4));
	my($major_subsys, $minor_subsys) = unpack("v2", substr($pe_image, $subsys_offset, 4));

	printf "MajorOperatingSystemVersion\t%d\n", $major_os;
	printf "MinorOperatingSystemVersion\t%d\n", $minor_os;
	printf "MajorImageVersion\t\t%d\n",         $major_image;
	printf "MinorImageVersion\t\t%d\n",         $minor_image;
	printf "MajorSubSystemVersion\t\t%d\n",     $major_subsys;
	printf "MajorSubSystemVersion\t\t%d\n",     $minor_subsys;
}
