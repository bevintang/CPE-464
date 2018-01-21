#include <stdio.h>
#include <pcap.h>

int main (int argc, char* argv[]){
	// Check for proper number of arguments
	if (argc != 2){
		fprintf(stderr, "Usage: trace TraceFile.pcap\n");
		return -1;
	}

	// Open pcap file
	
	return 0;
}