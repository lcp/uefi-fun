#!/usr/bin/perl

use strict;
use FileHandle;

# Define the GUID
my @EFI_CERT_SHA256_GUID = map hex, qw/0xc1c41626, 0x504c, 0x4092,
	0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28/;
my @EFI_CERT_X509_GUID = map hex, qw/0xa5c059a1, 0x94e4, 0x4aa7,
	0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72/;

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

sub print_guid(\@) {
	my (@guid) = @_;
	my $i;

	printf "0x%08x, 0x%04x, 0x%04x", $guid[0], $guid[1], $guid[2];
	for $i (3..10) {
		printf ", 0x%02x", $guid[$i];
	}
}

if ($#ARGV != 0) {
	print "Usage: print_authinfo <variable with AuthInfo>\n";
	exit;
}

my $authvar = read_file($ARGV[0]);
my $authvar_len = length($authvar);

# EFI_TIME (16 bytes)
#	UINT16	Year
#	UINT8	Month
#	UINT8	Day
#	UINT8	Hour
#	UINT8	Minute
#	UINT8	Second
#	UINT8	Pad1
#	UINT32	Nanosecond
#	INT16	TimeZone
#	UINT8	Daylight
#	UINT8	Pad2
my($year, $month, $day, $hour, $minute, $second, $pad1, $nanosecond, $timezone, $daylight, $pad2) =
	unpack("vC6VsC2", substr($authvar, 0, 16));

printf "Signing Time: %d/%02d/%02d %02d:%02d:%02d\n",
	$year, $month, $day, $hour, $minute, $second;

print "\n";

# WIN_CERTIFICATE (8 bytes)
#	UINT32	dwLength
#	UINT16	wRevision 		0x0200
#	UINT16	wCertificateType	0x0EF0 to 0x0EFF
my($dwLength, $wRevision, $wCertificateType) = unpack("VS2", substr($authvar, 16, 8));

# check the contents
die "invalid certificate length" if ($dwLength > $authvar_len);
die "invalid Revision" if ($wRevision != 0x200);
die "invalid certificate type"
	if ($wCertificateType != 0x0EF0 && $wCertificateType != 0x0EF1 && $wCertificateType != 0x0002);

my $wincert_type;

if ($wCertificateType == 0x0EF0) {
	$wincert_type = "WIN_CERT_TYPE_EFI_PKCS115"
} elsif ($wCertificateType == 0x0EF1) {
	$wincert_type = "WIN_CERT_TYPE_EFI_GUID"
} elsif ($wCertificateType == 0x0002) {
	$wincert_type = "WIN_CERT_TYPE_PKCS_SIGNED_DATA"	
}

printf "WIN_CERTIFICATE Length: %d\n", $dwLength;
printf "WIN_CERTIFICATE Revision: 0x%04x\n", $wRevision;
printf "WIN_CERTIFICATE Type: %s\n", $wincert_type;

print "\n";

my $skip = $dwLength + 16;
my $remain = $authvar_len - $skip;
my $siglist = $authvar;

while ($remain > 0) {
	$siglist = substr($siglist, $skip, $remain);

	# typedef struct _EFI_SIGNATURE_LIST {
	#        EFI_GUID        SignatureType;
	#        UINT32          SignatureListSize;
	#        UINT32          SignatureHeaderSize;
	#        UINT32          SignatureSize;
	#        //UINT8         SignatureHeader[SignatureHeaderSize];
	#        //EFI_SIGNATURE_DATA Signatures[...][SignatureSize];
	# } EFI_SIGNATURE_LIST;

	my(@guid) = unpack("VS2C8", $siglist);
	my $type = "Unknown";

	print "SignatureType: ";
	if (@guid ~~ @EFI_CERT_SHA256_GUID) {
		$type = "CERT_SHA256";
	} elsif (@guid ~~ @EFI_CERT_X509_GUID){
		$type = "CERT_X509";
	}
	print "$type\n";

	my($sig_list_size, $sig_hdr_size, $sig_size) = unpack("V3", substr($siglist, 16, 12));
	printf "SignatureListSize: %d\n", $sig_list_size;
	printf "SignatureHeaderSize: %d\n", $sig_hdr_size;
	printf "SignatureSize: %d\n", $sig_size;

	print "\n";

	$remain -= $sig_list_size;
	$skip = $sig_list_size;
	next if ($sig_hdr_size != 0);

	my $sig_num = ($sig_list_size - (16 + 4 + 4 + 4))/$sig_size;

	if ($type eq "CERT_X509" && $sig_num != 1) {
		print "Invalid SignatureListSize\n";
		next;
	}

	my $sig_skip = 16 + 4 + 4 + 4;
	my $sig_data;

	while ($sig_skip < $sig_list_size) {
		$sig_data = substr($siglist, $sig_skip, $sig_size);
		# typedef struct _EFI_SIGNATURE_DATA {
		#        EFI_GUID        SignatureOwner;
		#        UINT8           SignatureData[...];
		# } EFI_SIGNATURE_DATA;

		my(@owner) = unpack("VS2C8", $sig_data);
		my $data = substr($sig_data, 16, $sig_size - 16);

		print "\tOwner: ";
		&print_guid(@owner);
		print "\n";

		# print data
		if ($type eq "CERT_SHA256") {
			if (length($data) != 32) {
				print "Invalid SHA256\n";
			}
			my(@hash) = unpack("C32", $data);
			my $i;
			print "\tHash: ";
			foreach $i (@hash) {
				printf "%02x", $i;
			}
			print "\n";
		} elsif ($type eq "CERT_X509") {
			print "Not implemented\n";
		} else {
			print "Unknown\n";
		}

		print "\n";
		$sig_skip += $sig_size;
	}
}
