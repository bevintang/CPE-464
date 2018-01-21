#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>

/* Helper -- Check valid number of arguments */
void checkArgs(int argc){
	if (argc != 2){
		fprintf(stderr, "Usage: trace TraceFile.pcap\n");
		exit(EXIT_FAILURE);
	}
}

/* Helper -- Open a PCap File */
pcap_t* openPcapFile(const char* fname){
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* result = pcap_open_offline(fname, errbuf);

    // check extension for .pcap file
    if (!strstr(fname, ".pcap") != NULL){
        fprintf(stderr, "not a pcap file\n");
        exit(EXIT_FAILURE);
    }

    // try to open file
	if (result == NULL){
		fprintf(stderr, "file does not exist\n");
		exit(EXIT_FAILURE);
	}
	return result;
}

int main (int argc, char* argv[]){
	pcap_t* pcap_file;
	struct pcap_pkthdr** pkt_header;
	const u_char** pkt_data;
	const char* fname;


	checkArgs(argc);                   // Check for proper number of arguments
	fname = argv[1];
	pcap_file = openPcapFile(fname);   // open pcap file

	
	return 0;
}