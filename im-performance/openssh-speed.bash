#!/usr/bin/env bash

getbytes ()
{
	sed -n -e '/copied/s/\(.*s, .* kB.*\).*/\1/p'
}

set -o pipefail

bitss=1000000
timess=5000

echo "im-chacha-poly"
($(pwd)/../openssh-portable-intermac/ssh -vvv -o Compression=no -2 -c im-chacha-poly localhost -p 22222 -i ../openssh-portable-intermac/id_rsa_im exec bash -c \'"dd of=/dev/null obs=32K"\' < data) 2>&1

#echo "im-aes128-gcm"
#($(pwd)/../openssh-portable-intermac/ssh -o Compression=no -2 -c im-aes128-gcm localhost -p 22222 -i ../openssh-portable-intermac/id_rsa_im exec bash -c \'"dd of=/dev/null obs=32k"\' < data) 2>&1

#echo "aes128-gcm@openssh.com"
#($(pwd)/../openssh-portable-intermac/ssh -o Compression=no -2 -c aes128-gcm@openssh.com localhost -p 22222 -i ../openssh-portable-intermac/id_rsa_im exec bash -c \'"dd of=/dev/null obs=32k"\' < data) 2>&1

#echo "not cat"
#($(pwd)/../openssh-portable-intermac/ssh -o Compression=no -2 -c aes128-gcm@openssh.com localhost -p 22222 -i ../openssh-portable-intermac/id_rsa_im exec bash -c \'"dd of=/dev/null obs=32k"\' < DATA) 2>&1 



#($(pwd)/../openssh-portable-intermac/ssh -o Compression=no -2 -c chacha20-poly1305@openssh.com localhost -p 22222 -i ../openssh-portable-intermac/id_rsa_im exec bash -c \'"dd of=/dev/null obs=32k"\' < DATA) 2>&1 | getbytes

#($(pwd)/../openssh-portable-intermac/ssh -o Compression=no -2 -c chacha20-poly1305@openssh.com localhost -p 22222 -i ../openssh-portable-intermac/id_rsa_im pwd) 2>&1 | getbytes

#$(pwd)/../openssh-portable-intermac/ssh -vvv -c im-aes128-gcm -o Compression=no localhost -p 22222 -i ../openssh-portable-intermac/id_rsa_im
#dd if=/dev/zero bs=20000 count=1 2> /dev/null | $(pwd)/../openssh-portable-intermac/ssh -v -c im-aes128-gcm -o Compression=no localhost -p 22222 -i ../openssh-portable-intermac/id_rsa_im 
