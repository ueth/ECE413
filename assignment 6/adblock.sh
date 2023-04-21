#!/bin/bash
# You are NOT allowed to change the files' names!
domainNames="domainNames.txt"
domainNames2="domainNames2.txt"
IPAddressesSame="IPAddressesSame.txt"
IPAddressesDifferent="IPAddressesDifferent.txt"
adblockRules="adblockRules"

function adBlock() {
    if [ "$EUID" -ne 0 ];then
        printf "Please run as root.\n"
        exit 1
    fi
    if [ "$1" = "-domains"  ]; then
        # Sort the domain names and remove duplicates
        sort -u domainNames.txt > domainNames1.txt
        sort -u domainNames2.txt > domainNames3.txt

        # Find the common and unique domains
        # The -12 option specifies that comm should only print lines that are common to both files
        comm -12 domainNames1.txt domainNames3.txt > IPAddressesSame.txt
        # The -23 option specifies that it should only print lines that are unique to the first file
        comm -23 domainNames1.txt domainNames3.txt > IPAddressesDifferent1.txt
        # The -13 option specifies that it should only print lines that are unique to the second file
        comm -13 domainNames1.txt domainNames3.txt > IPAddressesDifferent2.txt

        # Concatenate the "different" files
        cat IPAddressesDifferent1.txt IPAddressesDifferent2.txt > IPAddressesDifferent.txt

        # Remove the temporary files
        rm domainNames1.txt domainNames3.txt IPAddressesDifferent1.txt IPAddressesDifferent2.txt
        true
            
    elif [ "$1" = "-ipssame"  ]; then
        while IFS= read -r ip || [[ -n "$ip" ]]; do
            iptables -A INPUT -s "$ip" -j DROP
        done < IPAddressesSame.txt
        true
    elif [ "$1" = "-ipsdiff"  ]; then
        while IFS= read -r ip || [[ -n "$ip" ]]; do
            iptables -A INPUT -s "$ip" -j REJECT
        done < IPAddressesDifferent.txt
        true
        
    elif [ "$1" = "-save"  ]; then
        iptables-save > "$adblockRules"
        true
        
    elif [ "$1" = "-load"  ]; then
        iptables-restore <$adblockRules
        true

    elif [ "$1" = "-reset"  ]; then
        iptables -F
        iptables -X
        # Set back to default
        iptables -P INPUT ACCEPT
        iptables -P OUTPUT ACCEPT
        iptables -P FORWARD DROP
        true

    elif [ "$1" = "-list"  ]; then
        iptables -L
        true
        
    elif [ "$1" = "-help"  ]; then
        printf "This script is responsible for creating a simple adblock mechanism. It rejects connections from specific domain names or IP addresses using iptables.\n\n"
        printf "Usage: $0  [OPTION]\n\n"
        printf "Options:\n\n"
        printf "  -domains\t  Configure adblock rules based on the domain names of '$domainNames' file.\n"
        printf "  -ipssame\t\t  Configure the DROP adblock rule based on the IP addresses of $IPAddressesSame file.\n"
	    printf "  -ipsdiff\t\t  Configure the DROP adblock rule based on the IP addresses of $IPAddressesDifferent file.\n"
        printf "  -save\t\t  Save rules to '$adblockRules' file.\n"
        printf "  -load\t\t  Load rules from '$adblockRules' file.\n"
        printf "  -list\t\t  List current rules.\n"
        printf "  -reset\t  Reset rules to default settings (i.e. accept all).\n"
        printf "  -help\t\t  Display this help and exit.\n"
        exit 0
    else
        printf "Wrong argument. Exiting...\n"
        exit 1
    fi
}

adBlock $1
exit 0
