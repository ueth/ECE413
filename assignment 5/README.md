# Assign 5

Network traffic monitoring using the Packet Capture library

## Compile

To compile everything use: make.

## How to run monitor

* To monitor live network traffic without a filter and a random assigned device by the program use: sudo ./pcap_ex -i random
* To monitor live network traffic with filter and a random assigned device by the program use: udo ./pcap_ex -i random -f "filterName"
* To monitor live network traffic without a filter and a specific device use: sudo ./pcap_ex -i "deviceName"
* To monitor live network traffic with filter and a specific device use: sudo ./pcap_ex -i "deviceName" -f "filterName"
* To read the pcap file use: sudo ./pcap_ex -r test_pcap_5mins.pcap
* To read help message use: sudo  ./pcap_ex -h

## GCC Version

gcc (Ubuntu 11.3.0-1ubuntu1~22.04) 11.3.0

### Can you tell if an incoming TCP packet is a retransmission? If yes, how? If not, why?

It is generally possible to determine whether an incoming TCP packet is a retransmission, by examining the TCP header fields of the packet. TCP retransmissions occur when a TCP sender does not receive an acknowledgement (ACK) for a segment it has sent. When this happens, the sender will retransmit the segment in order to ensure that the data is delivered to the receiver. One way to detect retransmissions is to check the sequence number of the TCP segment. The sequence number is a 32-bit field in the TCP header that identifies the position of the first data byte in the segment relative to the entire stream of data. When a TCP sender retransmits a segment, it will use the same sequence number as the original segment. By comparing the sequence number of an incoming segment with the sequence numbers of previously received segments, you can determine whether the segment is a retransmission.

### Can you tell if an incoming UDP packet is a retransmission? If yes, how? If not, why?

Unlike TCP, UDP does not have a built-in mechanism for retransmitting lost packets. When a UDP packet is lost, it is simply discarded and no action is taken to recover the lost data. As a result, it is generally not possible to determine whether an incoming UDP packet is a retransmission.

### Notes

It is worth noting that the method used for detecting retransmissions is not foolproof, as packet drops can occur for other reasons besides retransmission. However, it can be a useful method for detecting retransmissions in certain situations.