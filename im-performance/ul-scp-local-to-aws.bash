#!/usr/bin/env bash

set -o pipefail

UPLOAD_OR_DOWNLOAD=UPLOAD
BYTES=1MB

LOCAL=rhul
REMOTE=aws_london
HOST=ec2-52-56-140-16.eu-west-2.compute.amazonaws.com
PORT=22221
REMOTE_USER=ubuntu
SCP=/home/himsen/Projects/openssh-portable-intermac/scp

ID=aws_london
ID_LOCATION=/home/himsen/Projects/intermaclib/im-performance

TEST_DATA_FOLDER_NAME=testdata
LOCAL_DATA_FILE=loc.dat
LOCAL_DATA_FILE_LOCATION=/home/himsen/Projects/intermaclib/im-performance/$TEST_DATA_FOLDER_NAME
LOCAL_DATA=$LOCAL_DATA_FILE_LOCATION/$LOCAL_DATA_FILE
REMOTE_DATA_FILE=remote.dat
REMOTE_DATA_FILE_LOCATION=intermaclib/im-performance/$TEST_DATA_FOLDER_NAME
REMOTE_DATA=$REMOTE_DATA_FILE_LOCATION/$REMOTE_DATA_FILE

DATE=`date +%Y-%m-%d:%H:%M:%S`
LOG_FILE_NAME=$DATE\_scp.log

GREP_SCP='Bytes per second\|Bytes encrypted sent\|Bytes raw sent'

CIPHER_SUITES=("aes128-ctr" "hmac-md5" "aes128-ctr" "hmac-md5-etm@openssh.com" "aes128-ctr" "umac-64-etm@openssh.com" "aes128-ctr" 
	"hmac-sha1" "3des-cbc" "hmac-md5" "aes256-ctr" "hmac-sha2-512" "aes128-cbc" "hmac-sha1" "aes128-ctr" "hmac-ripemd160")
AUTH_CIPHER_SUITES=("chacha20-poly1305@openssh.com" "aes128-gcm@openssh.com")
INTERMAC_CIPHER_SUITES=("im-aes128-gcm-128" "im-chacha-poly-128" "im-aes128-gcm-256" "im-chacha-poly-256" "im-aes128-gcm-512"
	"im-chacha-poly-512" "im-aes128-gcm-1024" "im-chacha-poly-1024" "im-aes128-gcm-2048" "im-chacha-poly-2048"
	"im-aes128-gcm-4096" "im-chacha-poly-4096")

rm_remote_data () {

	ssh -i $ID_LOCATION/$ID $REMOTE_USER@$HOST "rm $REMOTE_DATA"

}

rm_local_data () {

	rm $LOCAL_DATA

}

generate_test_data () {
	
	dd if=/dev/zero of=$LOCAL_DATA bs=$BYTES count=1 &> /dev/null

}

scp_cipher_mac () {

	CIPHER=$1
	MAC=$2
	echo "$CIPHER + $MAC"
	echo "$CIPHER+$MAC" >> $LOG_FILE_NAME
	$SCP -v -c $CIPHER -o "MACs $MAC" -o 'Compression no' -i $ID_LOCATION/$ID -P $PORT $LOCAL_DATA $REMOTE_USER@$HOST:$REMOTE_DATA |& grep "$GREP_SCP" >> $LOG_FILE_NAME

}

scp_auth_cipher () {

	AUTHCIPHER=$1
	echo "$AUTHCIPHER"
	echo "$AUTHCIPHER" >> $LOG_FILE_NAME
	$SCP -v -c $AUTHCIPHER -o 'Compression no' -i $ID_LOCATION/$ID -P $PORT $LOCAL_DATA $REMOTE_USER@$HOST:$REMOTE_DATA |& grep "$GREP_SCP" >> $LOG_FILE_NAME

}

echo ""
echo "-----SCP BENCHMARK START-----"
echo ""

echo $LOCAL >> $LOG_FILE_NAME
echo $REMOTE >> $LOG_FILE_NAME
echo $UPLOAD_OR_DOWNLOAD >> $LOG_FILE_NAME
echo $BYTES >> $LOG_FILE_NAME

echo "Constructing temp data file:"
echo "File size: $BYTES"

generate_test_data

echo ""
echo "Executing SCP using cipher suite"
echo ""

# "normal" ciphers suites
for ((i=0; i<${#CIPHER_SUITES[@]}; i+=2));
do
	scp_cipher_mac "${CIPHER_SUITES[i]}" "${CIPHER_SUITES[i+1]}"
done

# AE cipher suites
for ((i=0; i<${#AUTH_CIPHER_SUITES[@]}; i+=1));
do
	scp_auth_cipher "${AUTH_CIPHER_SUITES[i]}"
done

# InterMAC cipher suites
for ((i=0; i<${#INTERMAC_CIPHER_SUITES[@]}; i+=1));
do
	scp_auth_cipher "${INTERMAC_CIPHER_SUITES[i]}"
done

rm_local_data
rm_remote_data

echo ""
echo "-----SCP BENCHMARK END-----"
echo ""
