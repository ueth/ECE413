# Assign 3

Enhanced Access Control Logging System.

## Compile

To compile everything use: make.

## How to update file_logging.log

To update file_logging.log use: make run

## How to run acmonitor

* To print mallicius users use: ./acmonitor -m
* To print a table of users that modified the file given and the number of modifications use: ./acmonitor -i [filename] (example: ./acmonitor -i test1.txt)
* For help use: ./acmonitor -h

## GCC Version

gcc (Ubuntu 11.3.0-1ubuntu1~22.04) 11.3.0

### Notes

* file_logging.log already has every possible case in it but feel free to update it.
* To make a deny - access case you need to remove all rights from noacc.txt with: chmod 000 noacc.txt
* In order to run anything you will need to install the GMP Library and Openssl