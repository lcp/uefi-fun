#!/usr/bin/perl

=head1 efiversion.pl

efiversion.pl - modify the version fields in the EFI image

=head1 SYNOPSIS

efiversion.pl [OPTIONS] -i input.efi -o output.efi

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
	"major-os=i" => \$major_os,
	"minor-os=i" => \$minor_os,
	"major-image=i" => \$major_image,
	"minor-image=i" => \$minor_image,
	"major-subsys=i" => \$major_subsys,
	"minor-subsys=i" => \$minor_subsys,
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

sub find_header_address($)
{
	my ($image) = @_;

	# e_magic must be 'M''Z'
	my ($e_magic) = unpack("v", substr($image, 0, 2));
	die "not a EFI Image\n" unless ($e_magic == 0x5A4D);

	my ($e_lfanew) = unpack("V", substr($image, 60, 4));

	# Match Signature 'P''E''\0''\0'
	my ($Signature) = unpack("V", substr($image, $e_lfanew, 4));
	die "not a PE Image\n" unless ($Signature == 0x4550);

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

my $pe_image;

if ($input) {
	$pe_image = read_file($input);
} else {
	usage(1);
}

my $e_lfanew = find_header_address($pe_image);
my $os_offset = $e_lfanew+64;
my $image_offset = $e_lfanew+68;
my $subsys_offset = $e_lfanew+72;

if ($output) {
	# Write the file
	&set_version(\$pe_image, $os_offset, $major_os) if ($major_os);
	&set_version(\$pe_image, $os_offset+2, $minor_os) if ($minor_os);
	&set_version(\$pe_image, $image_offset, $major_image) if ($major_image);
	&set_version(\$pe_image, $image_offset+2, $minor_image) if ($minor_image);
	&set_version(\$pe_image, $subsys_offset, $major_subsys) if ($major_subsys);
	&set_version(\$pe_image, $subsys_offset+2, $minor_subsys) if ($minor_subsys);
	&write_file($output, $pe_image);
} else {
	# Get the versions
	($major_os, $minor_os) = unpack("v2", substr($pe_image, $os_offset, 4));
	($major_image, $minor_image) = unpack("v2", substr($pe_image, $image_offset, 4));
	($major_subsys, $minor_subsys) = unpack("v2", substr($pe_image, $subsys_offset, 4));

	printf "MajorOperatingSystemVersion\t%d\n", $major_os;
	printf "MinorOperatingSystemVersion\t%d\n", $minor_os;
	printf "MajorImageVersion\t\t%d\n",         $major_image;
	printf "MinorImageVersion\t\t%d\n",         $minor_image;
	printf "MajorSubSystemVersion\t\t%d\n",     $major_subsys;
	printf "MajorSubSystemVersion\t\t%d\n",     $minor_subsys;
}
