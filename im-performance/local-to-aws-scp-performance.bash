#!/usr/bin/env bash

set -o pipefail

BYTES=10MB
SRC_HOST=local_rhul
DST_HOST=aws_london
HOST=ec2-52-56-140-16.eu-west-2.compute.amazonaws.com
PORT=22221
ID=aws_london
ID_LOCATION=/home/himsen/Projects/intermaclib/im-performance
DATA_FILE_NAME=output.dat
TEST_DATA_FOLDER_NAME=testdata
REMOTE_LOCATION=intermaclib/im-performance/$TEST_DATA_FOLDER_NAME/$DATA_FILE_NAME
REMOTE_PREFIX=home/ubuntu
SCP=/home/himsen/Projects/openssh-portable-intermac/scp
DATE=`date +%Y-%m-%d:%H:%M:%S`
LOG_FILE_NAME=$DATE\_scp.log
GREP_SCP='Bytes per second\|Bytes encrypted sent\|Bytes raw sent'
REMOTE_USER=ubuntu
CIPHER_SUITES=("aes128-ctr" "hmac-md5" "aes128-ctr" "hmac-md5-etm@openssh.com" "aes128-ctr" "umac-64-etm@openssh.com" "aes128-ctr" 
	"hmac-sha1" "3des-cbc" "hmac-md5" "aes256-ctr" "hmac-sha2-512" "aes128-cbc" "hmac-sha1" "aes128-ctr" "hmac-ripemd160")
AUTH_CIPHER_SUITES=("chacha20-poly1305@openssh.com" "aes128-gcm@openssh.com")
INTERMAC_CIPHER_SUITES=("im-aes128-gcm-128" "im-chacha-poly-128" "im-aes128-gcm-256" "im-chacha-poly-256" "im-aes128-gcm-512"
	"im-chacha-poly-512" "im-aes128-gcm-1024" "im-chacha-poly-1024" "im-aes128-gcm-2048" "im-chacha-poly-2048"
	"im-aes128-gcm-4096" "im-chacha-poly-4096")


rm_at_remote () {

	ssh -i $ID_LOCATION/$ID $REMOTE_USER@$HOST "rm $REMOTE_LOCATION"

}

scp_cipher_mac () {

	CIPHER=$1
	MAC=$2
	echo "$CIPHER + $MAC"
	echo "$CIPHER+$MAC" >> $LOG_FILE_NAME
	$SCP -v -c $CIPHER -o "MACs $MAC" -o 'Compression no' -i $ID_LOCATION/$ID -P $PORT $DATA_FILE_NAME $REMOTE_USER@$HOST:$REMOTE_LOCATION |& grep "$GREP_SCP" >> $LOG_FILE_NAME

}

scp_auth_cipher () {

	AUTHCIPHER=$1
	echo "$AUTHCIPHER"
	echo "$AUTHCIPHER" >> $LOG_FILE_NAME
	$SCP -v -c $AUTHCIPHER -o 'Compression no' -i $ID_LOCATION/$ID -P $PORT $DATA_FILE_NAME $REMOTE_USER@$HOST:$REMOTE_LOCATION |& grep "$GREP_SCP" >> $LOG_FILE_NAME

}

echo ""
echo "-----SCP BENCHMARK START-----"
echo ""

echo $SRC_HOST >> $LOG_FILE_NAME
echo $DST_HOST >> $LOG_FILE_NAME
echo $BYTES >> $LOG_FILE_NAME

echo "Constructing temp data file:"
echo "File size: $BYTES"

dd if=/dev/zero of=$DATA_FILE_NAME bs=$BYTES count=1 &> /dev/null

echo ""
echo "Executing SCP using cipher suite"
echo ""

# "normal" ciphers suites
for ((i=0; i<${#CIPHER_SUITES[@]}; i+=2));
do
	scp_cipher_mac "${CIPHER_SUITES[i]}" "${CIPHER_SUITES[i+1]}"
	rm_at_remote
done

# AE cipher suites
for ((i=0; i<${#AUTH_CIPHER_SUITES[@]}; i+=1));
do
	scp_auth_cipher "${AUTH_CIPHER_SUITES[i]}"
	rm_at_remote
done

# InterMAC cipher suites
for ((i=0; i<${#INTERMAC_CIPHER_SUITES[@]}; i+=1));
do
	scp_auth_cipher "${INTERMAC_CIPHER_SUITES[i]}"
	rm_at_remote
done

rm $DATA_FILE_NAME

echo ""
echo "-----SCP BENCHMARK END-----"
echo ""
