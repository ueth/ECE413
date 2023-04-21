# Assign 6

Network Scanning and Iptables

## How to run

sudo ./adblock.sh -choice

* -domains -> Find different and same domains in ‘domainNames.txt’ and ‘domainNames2.txt’ files and write them in “IPAddressesDifferent.txt" and IPAddressesSame.txt" respectively
* -ipssame -> Configure the DROP adblock rules based on the IP addresses of ‘IPAddressesSame.txt’ file.
* -ipsdiff -> Configure the REJECT adblock rules based on the IP addresses of ‘IPAddressesDifferent.txt’ file
* -save -> Save rules to ‘adblockRules’ file
* -load -> Load rules from ‘adblockRules’ file.
* -list -> List current rules
* -reset -> Reset rules to default settings.
* -help -> Display help and exit.

## GCC Version

gcc (Ubuntu 11.3.0-1ubuntu1~22.04) 11.3.0

## Questions
1. After configuring the adblock rules test your script by visiting your favourite
websites without any other adblocking mechanism (e.g., adblock browser
extensions). Can you see ads? Do they load? Some ads persist, why?

- The following reasons might explain why persistent ads exist:

* The ads might be transmitted over a secure connection: Some ads are transmitted using a secure connection over HTTPS, which makes it difficult for adblockers to block them.
* The ads might be loaded in a dynamic way: Some ads are loaded dynamically through JavaScript or other techniques.
* The ads might come from a trusted source: Some ads might not be blocked because they come from a trusted source that is exempt from the adblock rules.