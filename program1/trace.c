#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include "headerStructs.h"

#define IP 0x0800
#define ARP 0x0806
#define ETH_LEN 14;	//14-byte ethernet header

/* Helper -- Check valid number of arguments */
void checkArgs(int argc){
	if (argc != 2){
		fprintf(stderr, "Usage: trace TraceFile.pcap\n");
		exit(EXIT_FAILURE);
	}
}

/* Helper -- Open a PCap File */
void openPcapFile(const char* fname, pcap_t** pcap_file_ptr){
	char errbuf[PCAP_ERRBUF_SIZE];
	*pcap_file_ptr = pcap_open_offline(fname, errbuf);

    // check extension for .pcap file
    if (!(strstr(fname, ".pcap") != NULL)){
        fprintf(stderr, "not a pcap file\n");
        exit(EXIT_FAILURE);
    }

    // try to open file
	if (*pcap_file_ptr == NULL){
		fprintf(stderr, "file does not exist\n");
		exit(EXIT_FAILURE);
	}
}

/* Helper -- Extract ethernet header data into a struct & print contents */
void printEthernetHeader(const u_char** pkt_data){
	struct eth_header* header = (struct eth_header* ) (*pkt_data);

	printf("\tEthernet Header\n");
	printf("\t\tDest MAC: %s\n", ether_ntoa((const struct ether_addr *)header->dest_MAC));
	printf("\t\tSource MAC: %s\n", ether_ntoa((const struct ether_addr *)header->src_MAC));

	// Decipher type of ethernet
	if (ntohs(header->type) == ARP){
		printf("\t\tType: ARP\n\n");
	}
	else {
		printf("\t\tType: IP\n\n");
	}

	// Increment pkt_data pointer
	*pkt_data = *pkt_data + ETH_LEN;
}

/* Helper -- Extract IP header data into a struct & print contents */
void printIPHeader(const u_char* pkt_data, uint8_t* pseudo_header){
	struct ip_header* header = (struct ip_header* ) pkt_data;
	struct in_addr src_ip;
	struct in_addr dest_ip;
	src_ip.s_addr = header->src;
	dest_ip.s_addr = header->dest;

	printf("\tIP Header\n");
	printf("\t\tIP Version: %d\n", header->version);
	printf("\t\tHeader Len (bytes): %d\n", header->hdr_len*4);
	printf("\t\tTOS subfields:\n");
	printf("\t\t   Diffserv bits: %d\n", header->dsc);
	printf("\t\t   Diffserv bits: %d\n", header->ecn);
	printf("\t\tTTL: %d\n", header->ttl);
	printf("\t\tProtocol: %d\n", header->proto);
	//printf("\t\tChecksum: ")
	printf("\t\tSender IP: %s\n", inet_ntoa(src_ip));
	printf("\t\tDest IP: %s\n", inet_ntoa(dest_ip));
}

int main (int argc, char* argv[]){
	const char* fname;
	pcap_t* pcap_file;
	struct pcap_pkthdr* pkt_header;
	const u_char* pkt_data;
	int pkt_num = 0;
	int pkt_status = -3;
	uint8_t pseudo_header[1500];

	checkArgs(argc);                   // Check for proper number of arguments
	fname = argv[1];
	openPcapFile(fname, &pcap_file);   // open pcap file

	// Go through bytes:
	//struct eth_header *demo = (struct eth_header *) packet;
	//demo->src_MAC;

	// Grab a packet
	if ((pkt_status = pcap_next_ex(pcap_file, &pkt_header, &pkt_data)) != 1){
		fprintf(stderr, "pcap_next_ex: Unable to read next packet\n");
		exit(EXIT_FAILURE);
	}

	// Print packet number and length
	printf("Packet number: %d  Packet Len: %d\n\n", ++pkt_num, pkt_header->len);

	// Print Packet Data
	printEthernetHeader(&pkt_data);
	printIPHeader(pkt_data, pseudo_header);

	return 0;
}




