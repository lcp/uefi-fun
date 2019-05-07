#!/bin/bash
# Pack a given certificate into an initrd
# Mainly for HTTPS Boot in SLE/openSUSE

if [ "$1" == "" ] || [ "$2" == "" ]; then
	echo "Usage $0 cert.pem ssl.img"
	exit 0
fi
CERT_FILE=$1
OUTPUT=`realpath $2`

CERT_HASH=`openssl x509 -in $CERT_FILE -hash -noout`
if [ "$CERT_HASH" == "" ]; then
	echo "Failed to generate hash of certificate"
	exit 1
fi

TMP_ROOT=`mktemp -d`
if [ "$TMP_ROOT" == "" ] || [ ! -d "$TMP_ROOT" ]; then
	echo "Failed to create root dir"
	exit 1
fi

# Copy the certificate to the following directories
CERT_DIR="var/lib/ca-certificates/openssl/ var/lib/ca-certificates/pem/"
for dir in $CERT_DIR
do
	DEST="$TMP_ROOT/$dir"
	mkdir -p $DEST
	cp $CERT_FILE $DEST/my-ca.pem
	ln -sr $DEST/my-ca.pem $DEST/$CERT_HASH.0
done

# Go to the root and create the image
pushd $TMP_ROOT
find . | cpio --quiet -H newc -o | gzip -9 -n > $OUTPUT
popd

# Remove the root dir
rm -rf $TMP_ROOT
