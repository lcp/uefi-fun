#!/usr/bin/perl

=head1 svheader.pl

svheader.pl - show the Security version fields for Linux kernel

=head1 SYNOPSIS

svheader.pl [OPTIONS] FILE

=head1 OPTIONS

=over 4

=item B<--help, -h>

print help

=back

=head1 DESCRIPTION

A script to show the Security version fields for Linux kernel

Show the versions:
$ svheader.pl kernel-imag

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

my $help = '';
my $kernel;
my $kernel_length;

GetOptions(
	"help|h" => \$help,
) or usage(1);

usage(1) unless @ARGV;
usage(0) if ($help);

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
	$kernel = $contents;
	$kernel_length = $len;
}

sub find_secdata_offset($)
{
	my ($image) = @_;

	# 01FE/2 boot_flag: 0xAA55
	my ($boot_flag) = unpack("v", substr($image, 0x1fe, 2));
	die "Invalid boot flag\n" unless ($boot_flag == 0xAA55);

	# 0202/4 header: "hdrS" or 0x48647253 (big endian)
	my ($header) = unpack("N", substr($image, 0x202, 4));
	die "Not Linux\n" unless ($header == 0x48647253);

	# 0206/2 version: >= 0x020e
	my ($version) = unpack("v", substr($image, 0x206, 2));
	die "Old Linux kernel\n" unless ($version >= 0x20e);

	my ($secdata_offset) = unpack("v", substr($image, 0x268, 2));

	return $secdata_offset;
}

my ($file) = @ARGV;
read_file($file) if ($file);

my $secdata_offset = find_secdata_offset($kernel);

my $sec_hdr_size = unpack("v", substr($kernel, $secdata_offset, 2));
my ($dv, $sv) = unpack("Vv", substr($kernel, $secdata_offset+2, 6));

my $remaining = $kernel_length - ($secdata_offset + $sec_hdr_size);
my ($signer) = unpack("Z*", substr($kernel, $signer_offset, $remaining));

printf "Signer\t\t%s\n", $signer;
printf "Distro Ver.\t%d\n", $dv;
printf "Security Ver.\t%d\n", $sv;
