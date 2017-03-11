#1/usr/bin/env bash

set -o pipefail

BYTES=1MB
HOST=localhost
PORT=22222
ID=id_rsa_im
ID_LOCATION=.
DATA_FILE_NAME=output.dat
TEST_DATA_FOLDER_NAME=testdata
REMOTE_LOCATION=Projects/intermaclib/im-performance/$TEST_DATA_FOLDER_NAME/$DATA_FILE_NAME
REMOTE_PREFIX=home/himsen
SCP=$(pwd)/scp

rm_at_remote () {

	rm /$REMOTE_PREFIX/$REMOTE_LOCATION

}

scp_cipher_mac () {

	CIPHER=$1
	MAC=$2
	echo "$CIPHER + $MAC: "
	$SCP -c $CIPHER -o "MACs $MAC" -i $ID_LOCATION/$ID -P $PORT $DATA_FILE_NAME $HOST:$REMOTE_LOCATION

}

scp_auth_cipher () {

	AUTHCIPHER=$1
	echo "$AUTHCIPHER: "
	$SCP -c $AUTHCIPHER -i $ID_LOCATION/$ID -P $PORT $DATA_FILE_NAME $HOST:$REMOTE_LOCATION

}

echo ""
echo "-----SCP BENCHMARK START-----"
echo ""

echo "Construct temp data file:"
echo "File size: $BYTES"

dd if=/dev/zero of=$DATA_FILE_NAME bs=$BYTES count=1 &> /dev/null

echo ""
echo "scp test files"
echo ""

scp_cipher_mac "aes128-ctr" "hmac-md5"

rm_at_remote

scp_cipher_mac "aes128-ctr" "hmac-md5-etm@openssh.com"

rm_at_remote

scp_cipher_mac "aes128-ctr" "umac-64-etm@openssh.com"

rm_at_remote

scp_cipher_mac "aes128-cbc" "hmac-md5"

rm_at_remote

scp_auth_cipher "chacha20-poly1305@openssh.com"

rm_at_remote

scp_cipher_mac "aes128-ctr" "hmac-sha1"

rm_at_remote

scp_cipher_mac "3des-cbc" "hmac-md5"

rm_at_remote

scp_auth_cipher "aes128-gcm@openssh.com"

rm_at_remote

scp_cipher_mac "aes256-ctr" "hmac-sha2-512"

rm_at_remote

scp_cipher_mac "aes128-cbc" "hmac-sha1"

rm_at_remote

scp_cipher_mac "aes128-ctr" "hmac-ripemd160"

rm_at_remote

scp_auth_cipher "im-aes128-gcm"

rm_at_remote

scp_auth_cipher "im-chacha-poly"

rm_at_remote

rm $DATA_FILE_NAME


echo ""
echo "-----SCP BENCHMARK END-----"
echo ""
