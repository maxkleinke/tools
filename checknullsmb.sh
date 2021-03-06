#!/bin/bash
# simple script to check for null-session access on default shares
# Author: alwayslucky (@maxkleinke)

ip=$1
shares=('C$' 'D$' 'ADMIN$' 'IPC$' 'PRINT$' 'FAX$' 'SYSVOL' 'NETLOGON')

if [[ $# < 1 ]]; then
    echo "usage: ./checknullsmb.sh <ip>"
fi

for share in ${shares[*]}; do
    output=$(smbclient -U '%' -N \\\\$ip\\$share -c '')

    if [[ -z $output ]]; then
        echo "[+] creating a null session is possible for $share"
    else
        echo $output # echo error message (e.g. NT_STATUS_ACCESS_DENIED OR NT_STATUS_BAD_NETWORK_NAME)
    fi
done
