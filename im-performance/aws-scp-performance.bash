#!/usr/bin/env bash

set -o pipefail

BYTES=500MB
HOST=ec2-52-36-141-199.us-west-2.compute.amazonaws.com
PORT=22221
ID=aws_us_west_oregon
ID_LOCATION=.
DATA_FILE_NAME=output.dat
TEST_DATA_FOLDER_NAME=testdata
REMOTE_LOCATION=intermaclib/im-performance/$TEST_DATA_FOLDER_NAME/$DATA_FILE_NAME
REMOTE_PREFIX=ubuntu/
REMOTE_USER=ubuntu
SCP=/home/ubuntu/openssh-portable-intermac/scp
DATE=`date +%Y-%m-%d:%H:%M:%S`
LOG_FILE_NAME=$DATE\_scp.log
GREP_SCP='Bytes per second\|Bytes encrypted sent\|Bytes raw sent'

rm_at_remote () {

	ssh -i $ID_LOCATION/$ID $REMOTE_USER@$HOST "rm $REMOTE_LOCATION"
}

scp_cipher_mac () {

	CIPHER=$1
	MAC=$2
	echo "$CIPHER + $MAC"
	echo "$CIPHER+$MAC" >> $LOG_FILE_NAME
	$SCP -c $CIPHER -o "MACs $MAC" -o 'Compression no' -i $ID_LOCATION/$ID -P $PORT $DATA_FILE_NAME $HOST:$REMOTE_LOCATION |& grep "$GREP_SCP" >> $LOG_FILE_NAME

}

scp_auth_cipher () {

	AUTHCIPHER=$1
	echo "$AUTHCIPHER"
	echo "$AUTHCIPHER" >> $LOG_FILE_NAME
	$SCP -c $AUTHCIPHER -o 'Compression no' -i $ID_LOCATION/$ID -P $PORT $DATA_FILE_NAME $HOST:$REMOTE_LOCATION |& grep "$GREP_SCP" >> $LOG_FILE_NAME

}

echo ""
echo "-----SCP BENCHMARK START-----"
echo ""

echo "Constructing temp data file:"
echo "File size: $BYTES"

dd if=/dev/zero of=$DATA_FILE_NAME bs=$BYTES count=1 &> /dev/null

echo $bytes >> $LOG_FILE_NAME

echo ""
echo "Executing SCP using cipher suite"
echo ""

scp_cipher_mac "aes128-ctr" "hmac-md5"

rm_at_remote

#scp_cipher_mac "aes128-ctr" "hmac-md5-etm@openssh.com"

#rm_at_remote

#scp_cipher_mac "aes128-ctr" "umac-64-etm@openssh.com"

#rm_at_remote

#scp_cipher_mac "aes128-cbc" "hmac-md5"

#rm_at_remote

scp_auth_cipher "chacha20-poly1305@openssh.com"

rm_at_remote

#scp_cipher_mac "aes128-ctr" "hmac-sha1"

#rm_at_remote

scp_cipher_mac "3des-cbc" "hmac-md5"

rm_at_remote

scp_auth_cipher "aes128-gcm@openssh.com"

rm_at_remote

#scp_cipher_mac "aes256-ctr" "hmac-sha2-512"

#rm_at_remote

#scp_cipher_mac "aes128-cbc" "hmac-sha1"

#rm_at_remote

#scp_cipher_mac "aes128-ctr" "hmac-ripemd160"

#rm_at_remote

scp_auth_cipher "im-aes128-gcm-128"

rm_at_remote

scp_auth_cipher "im-chacha-poly-128"

rm_at_remote

#scp_auth_cipher "im-aes128-gcm-256"

#rm_at_remote

#scp_auth_cipher "im-chacha-poly-256"

#rm_at_remote

#scp_auth_cipher "im-aes128-gcm-512"

#rm_at_remote

#scp_auth_cipher "im-chacha-poly-512"

#rm_at_remote

#scp_auth_cipher "im-aes128-gcm-1024"

#rm_at_remote

#scp_auth_cipher "im-chacha-poly-1024"

#rm_at_remote

#scp_auth_cipher "im-aes128-gcm-2048"

#rm_at_remote

#scp_auth_cipher "im-chacha-poly-2048"

#rm_at_remote

#scp_auth_cipher "im-aes128-gcm-4096"

#rm_at_remote

#scp_auth_cipher "im-chacha-poly-4096"

#rm_at_remote

rm $DATA_FILE_NAME

echo ""
echo "-----SCP BENCHMARK END-----"
echo ""
