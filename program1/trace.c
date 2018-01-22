#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
//#include <netinet/if_ether.h>	//MAC_OSX
#include <netinet/ether.h>		//LINUX
#include "checksum.h"
#include "headerStructs.h"

#define ARP 0x0806
#define IP 8
#define PING_REPLY 0
#define PING_REQUEST 8
#define ICMP 1
#define TCP 6
#define UDP 17
#define ETH_LEN 14	//14-byte ethernet header

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
void printEthernetHeader(const u_char** pkt_data, struct eth_header** eth_head){
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
	*eth_head = header;
}

/* Helper -- Extract IP header data into a struct & print contents */
void printIPHeader(const u_char** pkt_data, struct ip_header** ip_head){
	struct ip_header* header = (struct ip_header* ) (*pkt_data);
	struct in_addr src_ip;
	struct in_addr dest_ip;
	src_ip.s_addr = header->src;
	dest_ip.s_addr = header->dest;

	printf("\tIP Header\n");
	printf("\t\tIP Version: %d\n", header->version);
	printf("\t\tHeader Len (bytes): %d\n", header->hdr_len*4);
	printf("\t\tTOS subfields:\n");
	printf("\t\t   Diffserv bits: %d\n", header->dsc);
	printf("\t\t   ECN bits: %d\n", header->ecn);
	printf("\t\tTTL: %d\n", header->ttl);

	// Print Protocol
	uint8_t protocol = header->proto;
	if (protocol == ICMP)
		printf("\t\tProtocol: ICMP\n");
	else if (protocol == TCP)
		printf("\t\tProtocol: TCP\n");
	else if (protocol == UDP)
		printf("\t\tProtocol: UDP\n");
	else
		printf("\t\tProtocol: Unknown\n");
	
	// Checksum
	if (in_cksum((unsigned short*)*pkt_data, 4*header->hdr_len) == 0)
		printf("\t\tChecksum: Correct (0x%04x)\n", ntohs(header->checksum));
	else
		printf("\t\tChecksum: Incorrect (0x%04x)\n", ntohs(header->checksum));
	printf("\t\tSender IP: %s\n", inet_ntoa(src_ip));
	printf("\t\tDest IP: %s\n\n", inet_ntoa(dest_ip));

	*pkt_data = *pkt_data + 4*header->hdr_len;
	*ip_head = header;
}

/* Helper -- Extract ARP header data into a struct & print contents */
void printARPHeader(const u_char* pkt_data){
	struct arp_header* header = (struct arp_header* ) pkt_data;
	struct in_addr send_ip;
	struct in_addr targ_ip;
	send_ip.s_addr = header->send_ip;
	targ_ip.s_addr = header->targ_ip;

	printf("\tARP header\n");
	// Opcode
	if (ntohs(header->opcode) == 0x0001)
		printf("\t\tOpcode: Request\n");
	else if (ntohs(header->opcode) == 0x0002)
		printf("\t\tOpcode: Reply\n");
	else
		printf("\t\tOpcode: 0x%04x\n", ntohs(header->opcode));
	printf("\t\tSender MAC: %s\n", ether_ntoa((const struct ether_addr *)header->send_MAC));
	printf("\t\tSender IP: %s\n", inet_ntoa(send_ip));
	printf("\t\tTarget MAC: %s\n", ether_ntoa((const struct ether_addr *)header->targ_MAC));
	printf("\t\tTarget IP: %s\n\n\n", inet_ntoa(targ_ip));
}

/* Helper -- Extract ICMP header data into a struct & print contents */
void printICMPHeader(const u_char* pkt_data) {
	struct icmp_header* header = (struct icmp_header* ) pkt_data;

	printf("\tICMP Header\n");
	if (header->type == PING_REPLY)
		printf("\t\tType: Reply\n\n");
	else if (header->type == PING_REQUEST)
		printf("\t\tType: Request\n\n");
	else
		printf("\t\tType: %d\n\n", header->type);
}

/* Helper -- Extract UDP header data into a struct & print contents */
void printUDPHeader(const u_char* pkt_data) {
	struct udp_header* header = (struct udp_header* ) pkt_data;

	printf("\tUDP Header\n");
	// Print either port number or 'DNS'
	if (ntohs(header->src_port) != 53)
		printf("\t\tSource Port:  %d\n", ntohs(header->src_port));
	else
		printf("\t\tSource Port:  DNS\n");

	if (ntohs(header->dest_port) != 53)
		printf("\t\tDest Port:  %d\n\n", ntohs(header->dest_port));
	else
		printf("\t\tDest Port:  DNS\n\n");
}

char* printYesNo(uint8_t flag){
	if (flag == 1)
		return "Yes";
	else
		return "No";
}

/* Helper -- Extract TCP header data into a struct & print contents */
void printTCPHeader(const u_char* pkt_data, uint8_t* pseudo_header, int tcp_size) {
	struct tcp_header* header = (struct tcp_header* ) pkt_data;

	printf("\tTCP Header\n");
	// Print either port number or 'HTTP'
	if (ntohs(header->src_port) != 80)
		printf("\t\tSource Port:  %d\n", ntohs(header->src_port));
	else
		printf("\t\tSource Port:  HTTP\n");

	if (ntohs(header->dest_port) != 80)
		printf("\t\tDest Port:  %d\n", ntohs(header->dest_port));
	else
		printf("\t\tDest Port:  HTTP\n");
	printf("\t\tSequence Number: %u\n", ntohl(header->seq));
	printf("\t\tACK Number: %u\n", ntohl(header->ack_num));
	printf("\t\tData Offset (bytes): %d\n", 4*header->offset);
	printf("\t\tSYN Flag: %s\n", printYesNo(header->syn));
	printf("\t\tRST Flag: %s\n", printYesNo(header->rst));
	printf("\t\tFIN Flag: %s\n", printYesNo(header->fin));
	printf("\t\tACK Flag: %s\n", printYesNo(header->ack));
	printf("\t\tWindow Size: %d\n", ntohs(header->window_size));

	// Concat tcp header to pseudo header
	memcpy(pseudo_header+12, pkt_data, tcp_size);

	// Checksum
	if (in_cksum((unsigned short*)pseudo_header, tcp_size + 12) == 0)
		printf("\t\tChecksum: Correct (0x%04x)\n\n", ntohs(header->checksum));
	else
		printf("\t\tChecksum: Incorrect (0x%04x)\n\n", ntohs(header->checksum));

}

/* Helper -- Construct pseudo header. Return size of packet */
int setupPseudoHeader(uint8_t* pseudo_header, struct ip_header* ip_data){
	uint16_t size = ntohs(ip_data->tot_len) - 4*ip_data->hdr_len;

	memcpy(pseudo_header, &(ip_data->src), sizeof(ip_data->src));
	memcpy(pseudo_header+4, &(ip_data->dest), sizeof(ip_data->dest));
	pseudo_header[8] = 0;
	pseudo_header[9] = ip_data->proto;

	// Calculate TCP Size
	pseudo_header[10] = ((size & 0xff00) >> 8);	// Mask last byte, shift to end
	pseudo_header[11] = size & 0x00ff;

	return size;
}

int main (int argc, char* argv[]){
	const char* fname;
	pcap_t* pcap_file;
	struct pcap_pkthdr* pkt_header;
	const u_char* pkt_data;
	int pkt_num = 0;
	int pkt_status = -3;
	struct eth_header* eth_data;
	struct ip_header* ip_data;
	uint8_t pseudo_header[1500];
	int tcp_size = 0;

	checkArgs(argc);                   // Check for proper number of arguments
	fname = argv[1];
	openPcapFile(fname, &pcap_file);   // open pcap file

	while ((pkt_status = pcap_next_ex(pcap_file, &pkt_header, &pkt_data)) != -2) {
		// Grab a packet
		if (pkt_status != 1){
			fprintf(stderr, "pcap_next_ex: Unable to read next packet\n");
			exit(EXIT_FAILURE);
		}

		// Print packet number and length
		printf("Packet number: %d  Packet Len: %d\n\n", ++pkt_num, pkt_header->len);
		printEthernetHeader(&pkt_data, &eth_data);

		// Print either IP or ARP
		if (eth_data->type == IP){
			printIPHeader(&pkt_data, &ip_data);
			tcp_size = setupPseudoHeader(pseudo_header, ip_data);
		}
		else {
			printARPHeader(pkt_data);
			continue;
		}

		// Print either ICMP, TCP, or default to UDP
		switch (ip_data->proto){
			case ICMP :
				printICMPHeader(pkt_data);
				break;
			case TCP :
				printTCPHeader(pkt_data, pseudo_header, tcp_size);
				break;
			case UDP :
				printUDPHeader(pkt_data);
				break;
			default:
				break;
		}
	}

	return 0;
}




