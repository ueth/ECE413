#include <stdio.h>
#include <stdlib.h> 
#include <string.h> 
#include <stdbool.h>
#include <sys/socket.h>
#include <unistd.h>
#include <signal.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <arpa/inet.h> 
#include <net/ethernet.h>
#include <netinet/udp.h>	
#include <netinet/tcp.h>	
#include <netinet/ip.h>	


pcap_t *handle;
int total_flows = 0;
int tcp_flows = 0;
int udp_flows = 0;
int total_packets = 0;
int tcp_packets = 0;
int udp_packets = 0;
int tcp_bytes = 0;
int udp_bytes = 0;
FILE *fp;
// Global variable to store the open mode of the pcap_t handle
int open_mode;

enum {
    PCAP_OPEN_OFFLINE,
    PCAP_OPEN_LIVE
};

void print_stats(){
	printf("Total network flows captured         -> %d\n", total_flows);
	printf("TCP network flows captured           -> %d\n", tcp_flows);
	printf("UDP network flows captured           -> %d\n", udp_flows);
	printf("Total number of packets received     -> %d\n", total_packets);
	printf("Total number of TCP packets received -> %d\n", tcp_packets);
	printf("Total number of UDP packets received -> %d\n", udp_packets);
	printf("Total number of TCP bytes received   -> %d\n", tcp_bytes);
	printf("Total number of UDP bytes received   -> %d\n", udp_bytes);
}

typedef struct net_flow{
	char source_ip[INET_ADDRSTRLEN];
	char dest_ip[INET_ADDRSTRLEN];
	unsigned int protocol;
	unsigned int source_port;
	unsigned int dest_port;
	bool retrnsm_flag;

	struct net_flow* next;
};

struct net_flow *net_flow_head = NULL;

/**
 * Check to see if a net flow already exists
*/
bool is_in_list(struct net_flow *net_f, char *source_ip, char *dest_ip, int protocol, unsigned int source_port, unsigned int dest_port){
	if(net_f == NULL)
		return false;

	struct net_flow *temp_f = net_f;

    while(temp_f != NULL){
        if((strcmp(temp_f->source_ip, source_ip) == 0) && (strcmp(temp_f->dest_ip, dest_ip) == 0) && temp_f->protocol == protocol && temp_f->source_port == source_port && temp_f->dest_port == dest_port)
            return true;

        temp_f = temp_f->next;
    }
	return false;
}

/**
 * Add new net flow
*/
void add_new_net_flow(struct net_flow *net_f, char *source_ip, char *dest_ip, int protocol, unsigned int source_port, unsigned int dest_port){
	struct net_flow *new_f = (struct net_flow *)malloc(sizeof(struct net_flow));
	struct net_flow *temp = net_f;
	struct pcap_stat stats;

	//First net flow
	if (net_f == NULL){
		memcpy(new_f->source_ip, source_ip, INET_ADDRSTRLEN);
		memcpy(new_f->dest_ip, dest_ip, INET_ADDRSTRLEN);

		new_f->protocol = protocol;
		new_f->source_port = source_port;
		new_f->dest_port = dest_port;
		new_f->next = NULL;
		net_flow_head = new_f;

		//Increase stats
		total_flows++;
		if(new_f->protocol == IPPROTO_TCP){
			if (pcap_stats(handle, &stats) < 0) {
    			fprintf(stderr, "Couldn't get capture statistics: %s\n", pcap_geterr(handle));
				tcp_flows++;
    			return;
  			}
			if (stats.ps_drop > 0) {
    			printf("Packet is retransmitted\n");
				new_f->retrnsm_flag = true;
  			}
			else new_f->retrnsm_flag = false;
			
			tcp_flows++;
		}
		else if (new_f->protocol == IPPROTO_UDP){
			udp_flows++;
			new_f->retrnsm_flag = false;
		}

		return;
	}

	while(temp->next != NULL)
		temp = temp->next;

	temp->next = new_f;
	memcpy(new_f->source_ip, source_ip, INET_ADDRSTRLEN);
	memcpy(new_f->dest_ip, dest_ip, INET_ADDRSTRLEN);
	new_f->protocol = protocol;
	new_f->source_port = source_port;
	new_f->dest_port = dest_port;
	new_f->next = NULL;

	total_flows++;
	if(new_f->protocol == IPPROTO_TCP){
		if (pcap_stats(handle, &stats) < 0) {
    		fprintf(stderr, "Couldn't get capture statistics: %s\n", pcap_geterr(handle));
			tcp_flows++;
    		return;
  		}
		if (stats.ps_drop > 0) {
    		printf("Packet is retransmitted\n");
			new_f->retrnsm_flag = true;
  		}
		else new_f->retrnsm_flag = false;
			
		tcp_flows++;
	}
	else if (new_f->protocol == IPPROTO_UDP){
		udp_flows++;
		new_f->retrnsm_flag = false;
	}
}

/**
 * Handle TCP packets
*/
void tcp_handle(const u_char * packet, int size){
	++tcp_packets;
	char source_ip_addr[INET_ADDRSTRLEN];
	char destination_ip_addr[INET_ADDRSTRLEN];

	const struct ip * ip_header = (struct ip *)(packet + sizeof(struct ether_header) );

	struct ether_header *packet_ptr = (struct ether_header*)packet;

	//Support IPv4 and IPv6 packets
	if (ntohs(packet_ptr->ether_type) != ETHERTYPE_IP && ntohs(packet_ptr->ether_type) != ETHERTYPE_IPV6) {
		printf("Only IPv4 and IPv6 are supported, skipped.\n");
		return;
	}
	
	// Convert the IP addresses from numerical representation to string
	inet_ntop(AF_INET, &(ip_header->ip_src), source_ip_addr, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(ip_header->ip_dst), destination_ip_addr, INET_ADDRSTRLEN);
	
	//skip the Ethernet and IP headers in the packet data and point to the tcp_header
	struct tcphdr *tcp_header =(struct tcphdr*)(packet + ip_header->ip_hl*4 + sizeof(struct ethhdr));

	// int header_size =  sizeof(struct ethhdr) + ip_len + tcp_header->doff*4;
	int payload_length = size - (tcp_header->doff*4 + tcp_header->doff*4);

	u_int *payload = (u_int *)(packet + sizeof(struct ether_header) + ip_header->ip_hl*4 + tcp_header->doff*4);

	tcp_bytes += size;
	
	if(!is_in_list(net_flow_head, source_ip_addr, destination_ip_addr, (unsigned int)ip_header->ip_p, ntohs(tcp_header->source), ntohs(tcp_header->dest)))
		add_new_net_flow(net_flow_head,source_ip_addr,destination_ip_addr,(unsigned int)ip_header->ip_p,ntohs(tcp_header->source),ntohs(tcp_header->dest));
	
	printf("Source IP addr: %s. Dest IP addr: %s. Protocol: TCP. Source Port: %u. Dest Port: %u. Header Length: %d. Payload Length: %d. Payload memory addr: %8X\n", source_ip_addr, destination_ip_addr, ntohs(tcp_header->source), ntohs(tcp_header->dest), (unsigned int)tcp_header->doff*4, payload_length, payload);

	if(open_mode == PCAP_OPEN_LIVE){
		char line[512];

		/*Generate log line*/
		sprintf(line,"Source IP addr: %s. Dest IP addr: %s. Protocol: TCP. Source Port: %u. Dest Port: %u. Header Length: %d. Payload Length: %d. Payload memory addr: %8X\n", source_ip_addr, destination_ip_addr, ntohs(tcp_header->source), ntohs(tcp_header->dest), (unsigned int)tcp_header->doff*4, payload_length, payload);

		fprintf(fp, line, strlen(line));
	}

	return;
}

void udp_handle(const u_char * packet, int size){
	udp_packets++;
	char source_ip_addr[INET_ADDRSTRLEN];
	char dest_ip_addr[INET_ADDRSTRLEN];

	const struct ip * ip_header = (struct ip *)(packet  + sizeof(struct ethhdr) );
	struct ether_header *eptr = (struct ether_header*)packet;

	if (ntohs(eptr->ether_type) != ETHERTYPE_IP && ntohs(eptr->ether_type) != ETHERTYPE_IPV6) {
		printf("Only IPv4 and IPv6 are supported, skipped.\n");
		return;
	}
	
	inet_ntop(AF_INET, &(ip_header->ip_src), source_ip_addr, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip_addr, INET_ADDRSTRLEN);
	

	struct udphdr *udp_header = (struct udphdr*)(packet + ip_header->ip_hl*4 + sizeof(struct ethhdr));

	int header_size =  sizeof(struct ethhdr) + ip_header->ip_hl*4 +sizeof(udp_header);
	int payload_length = size - header_size;

	u_int *payload = (u_int *)(packet + sizeof(struct ether_header) + ip_header->ip_hl*4 + udp_header->len);

	udp_bytes += size;

	if(!is_in_list(net_flow_head, source_ip_addr,dest_ip_addr, (unsigned int)ip_header->ip_p, ntohs(udp_header->source), ntohs(udp_header->dest)))
		add_new_net_flow(net_flow_head, source_ip_addr, dest_ip_addr,(unsigned int)ip_header->ip_p,ntohs(udp_header->source),ntohs(udp_header->dest));
	
	printf("Source IP addr: %s. Dest IP addr: %s. Protocol: TCP. Source Port: %u. Dest Port: %u. Header Length: %d. Payload Length: %d. Payload memory addr: %8X\n", source_ip_addr, dest_ip_addr, ntohs(udp_header->source), ntohs(udp_header->dest), (unsigned int)udp_header->len, payload_length, payload);

	if(open_mode == PCAP_OPEN_LIVE){
		char line[512];

		/*Generate log line*/
		sprintf(line,"Source IP addr: %s. Dest IP addr: %s. Protocol: TCP. Source Port: %u. Dest Port: %u. Header Length: %d. Payload Length: %d. Payload memory addr: %8X\n", source_ip_addr, dest_ip_addr, ntohs(udp_header->source), ntohs(udp_header->dest), (unsigned int)udp_header->len, payload_length, payload);

		fprintf(fp, line, strlen(line));
	}

	return;
}

void packet_callback(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet){
	int size = header->len;
	const struct ip *ip_header = (struct ip*)(packet + sizeof(struct ether_header));
	++total_packets;

	switch (ip_header->ip_p) {
		case IPPROTO_TCP: 
			tcp_handle(packet, size);
			break;
		
		case IPPROTO_UDP: 
			udp_handle(packet, size);
			break;

		default: 
			printf("No TCP or UDP protocol, skipped.\n");
			break;		
	}
}

void terminate_process(int signum){
	pcap_breakloop(handle);
	pcap_close(handle);
	close(fp);
	printf("\npcal_loop Terminated\n");
}

void handle_live_traffic(char *dev, char *filter){
    char errbuf[PCAP_ERRBUF_SIZE];	 /* error buffer */
    int timeout = 3000;				 /* Timeout threshold */
	struct bpf_program bfp;           /* compiled filter program (expression) */
	bpf_u_int32 mask;                /* subnet mask */
    bpf_u_int32 net;                 /* ip */
	fp = fopen("log.txt", "w");

    /* Find a device */\
	if(dev = "random")
    	dev = pcap_lookupdev(errbuf);

    if (dev == NULL) {
        printf("Error finding device: %s\n", errbuf);
		exit(EXIT_FAILURE);
	}
	
	 /* get network number and mask associated with capture device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n",dev, errbuf);
        net = 0;
        mask = 0;
    }

	/* print capture info */
    printf("Device: %s\n", dev);
	if(filter == NULL) printf("No filter\n");
    else printf("Filter expression: %s\n", filter);

	open_mode = PCAP_OPEN_LIVE;

    handle = pcap_open_live(dev,BUFSIZ,0,timeout,errbuf);   

    if(handle == NULL){
        printf("Error for pcap_open_live(): %s\n",errbuf);
		return ;
	}

	if(filter != NULL){
		/* compile the filter expression */
        if (pcap_compile(handle, &bfp, filter, 0, net) == -1) {
            fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
            exit(EXIT_FAILURE);
        }

        /* apply the compiled filter */
        if (pcap_setfilter(handle, &bfp) == -1) {
            fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
            exit(EXIT_FAILURE);
        }
	}

	//SIGINT -> CTRL+C
	signal(SIGINT, terminate_process);
	
	pcap_loop(handle,timeout,packet_callback,NULL);	
	
	print_stats();

	return;
}

void handle_file_traffic(char *file_name){
	char errbuf[PCAP_ERRBUF_SIZE];	
	int timeout = 1000;

	open_mode = PCAP_OPEN_OFFLINE;

	handle = pcap_open_offline(file_name,errbuf);

	if(handle != NULL){
		pcap_loop(handle, -1, packet_callback ,NULL);
		print_stats();
	}
	else 
		printf("Error opening file!\n");

	return;
}

void print_help(){
	printf("-i Network interface name (if you enter \"random\" the program will choose a random device)");
	printf("-r Packet capture file name");
	printf("-f Filter expression");
	printf("-h Help message");
}

int main(int argc, char* argv[]){
    int ch;
	char *device;
	char *filter;

	device = NULL;
	filter = NULL;

    while ((ch = getopt(argc, argv, "f:i:r:h")) != -1) {
		switch(ch) {
		case 'i':
			device = strdup(optarg);
			break;
		case 'f':
			filter = strdup(optarg);
			break;
		case 'r':
			handle_file_traffic(optarg);
			exit(0);
			break;
		case 'h':
			print_help();
			exit(1);
		default:
            printf("Wrong arguments\n");
			exit(2);
		}		
	} 

	handle_live_traffic(device, filter);

    return 0;
}