#!/usr/bin/env bash

#From https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Security_Guide/sect-Security_Guide-Encryption-OpenSSL_Intel_AES-NI_Engine.html

echo 
echo "(This is only tested on Linux systems)"
echo "Ask if the processor has the AES instruction set:"
grep -1 -o aes /proc/cpuinfo
echo 
echo "Now test speed"
echo "First (presumably without NI support):"
openssl speed aes-128-cbc
echo "Second (presumably with NI support):"
openssl speed -evp aes-128-cbc
echo 
echo "Second speed test should be faster than the first speed test"

