/******************************************************************************
* tcp_client.c
*
*****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "networks.h"

#define MAXBUF 1400
#define DEBUG_FLAG 1
#define MESSAGE 5	// flag = 5
#define BLOCK 69
#define UNBLOCK 70
#define LIST 10		// flag = 10
#define EXIT 8		// flag = 8
#define NEW_CLIENT 69
#define xstr(a) str(a)
#define str(a) #a

void sendToServer(int socketNum, uint8_t* sendBuf, int sendLen, int sendFlag);
void checkArgs(int argc, char * argv[]);

void attachChatHeader(uint8_t* sendBuf, uint16_t size, uint8_t flag) {
	uint16_t trueSize = htons(size + 3);
	sendBuf[0] = ((trueSize & 0xff00) >> 8);	// insert leading byte
	sendBuf[1] = trueSize & 0x00ff;				// insert trailing byte
	sendBuf[2] = flag;
}

void initConnection(int socketNum, char** argv, uint8_t* sendBuf) {
	attachChatHeader(sendBuf, strlen(argv[1]) + 3, NEW_CLIENT);
	memcpy(sendBuf+3, argv[1], strlen(argv[1]));
	sendToServer(socketNum, sendBuf, strlen(argv[1]) + 3, 0);
}

int parseID(char* token) {
	int returnVal = -1;

	if (memcmp(token, "%M", 2) == 0 || memcmp(token, "%m", 2) == 0) {
		returnVal = MESSAGE;
	}
	else if (memcmp(token, "%B", 2) == 0 || memcmp(token, "%b", 2) == 0) {
		returnVal = BLOCK;
	}
	else if (memcmp(token, "%U", 2) == 0 || memcmp(token, "%u", 2) == 0) {
		returnVal = UNBLOCK;
	}
	else if (memcmp(token, "%L", 2) == 0 || memcmp(token, "%l", 2) == 0) {
		returnVal = LIST;
	}
	else if (memcmp(token, "%E", 2) == 0 || memcmp(token, "%e", 2) == 0) {
		returnVal = EXIT;
	}

	return returnVal;
}

uint16_t getPacketLength(char** tokens, int numTokens) {
	uint16_t totalLength = 0;
	int i = 0;

	for (i = 0; i < numTokens; i++) {
		totalLength += strlen(tokens[i]);
	}
	return totalLength;
}

void sendMessage(uint8_t* sendBuf, char* input, int socketNum, uint8_t* thisHandle) {
	uint16_t totalLength = 0;
	int bufPos = 3;		// position after chat-header
	int curLength = 0;	// length of each token
	char* tokens[30];
	int i = 0, numTokens = 0;

	// Split input into %M tokens -- making sure to leave 
	tokens[0] = strtok(input, " ");
	for (i = 0; i < 2; i++) {
		tokens[i] = strtok(NULL, " ");	// grab command and number of handles
	}
	/*
		I STOPPED RIGHT HERE BEFORE SHOWERING
	*/

	totalLength = getPacketLength(tokens, numTokens);

	// Setup sendBuf for Message Send
	attachChatHeader(sendBuf, totalLength, (uint8_t)MESSAGE);
	for (i = 0; i < numTokens; i++) {
		curLength = strlen(tokens[i]);
		memcpy(sendBuf+bufPos, tokens[i], curLength);
		bufPos += curLength;
		printf("\tClient side String: %s\n", tokens[i]);
		printf("\tLast letter in buf: %c\n", sendBuf[bufPos-1]);
	}

	sendToServer(socketNum, sendBuf, totalLength, 0);
}

void parseCommand(char* input, uint8_t* sendBuf, int socketNum, uint8_t* thisHandle) {
	int commandID = -1;
	char command[2];
	memcpy(command, input, 2);

	// // Fill token array
	// while (tokens[i] != NULL) {
	// 	++i;
	// 	tokens[i] = strtok(NULL, " ");
	// }
	//numTokens = i;


	bzero(sendBuf, MAXBUF);
	commandID = parseID(command);
	switch (commandID) {
		case MESSAGE:
			printf("\tMessage command!\n");
			sendMessage(sendBuf, input, socketNum, thisHandle);
			break;
		case BLOCK:
			printf("\tBlock command!\n");
			break;
		case UNBLOCK:
			printf("\tUnblock command!\n");
			break;
		case LIST:
			printf("\tList command!\n");
			break;
		case EXIT:
			printf("\tExit command!\n");
			break;
		case -1:
			printf("\tCommand not recognized\n");
			break;
	}
}

void run (int socketNum, uint8_t* sendBuf, uint8_t* thisHandle) {
	char input[MAXBUF];
	//int sendLen = 0;        	// amount of data to send

	while (memcmp(sendBuf, "%E", 2) != 0 && memcmp(sendBuf, "%e", 2) != 0){
		bzero(input, MAXBUF);
		printf("$: ");
		scanf(" %" xstr(MAXBUF) "[^\n]%*[^\n]", input);
		parseCommand(input, sendBuf, socketNum, thisHandle);
	}
	send(socketNum, sendBuf, -1, 0);
}

int main(int argc, char * argv[])
{
	int socketNum = 0;
	uint8_t sendBuf[MAXBUF];   	// data buffer
	checkArgs(argc, argv);
	uint8_t thisHandle[100];

	socketNum = tcpClientSetup(argv[2], argv[3], DEBUG_FLAG);
	initConnection(socketNum, argv, sendBuf);
	memcpy(handle, argv[1], strlen(argv[1]));
	run(socketNum, sendBuf, thisHandle);
	close(socketNum);
	
	return 0;
}

void sendToServer(int socketNum, uint8_t* sendBuf, int sendLen, int sendFlag)
{
	int sent = 0;	// actual amount of data sent

	sent = send(socketNum, sendBuf, sendLen+1, 0);
	if (sent < 0)
	{
		perror("send call");
		exit(-1); 
	}
	printf("\tString sent: %s\n", sendBuf+3);
	printf("\tAmount of data sent: %d\n", sent);
}

void checkArgs(int argc, char * argv[])
{
	/* check command line arguments  */
	if (argc != 4)
	{
		printf("usage: %s handle-name host-name port-number \n", argv[0]);
		exit(1);
	}
}
