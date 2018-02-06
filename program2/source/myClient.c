/******************************************************************************
* tcp_client.c
*
*****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
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

#define MAXBUF 1401
#define DEBUG_FLAG 1
#define MESSAGE 5	// flag = 5
#define BLOCK 69
#define UNBLOCK 70
#define LIST 10		// flag = 10
#define EXIT 8		// flag = 8
#define NEW_CLIENT 69
#define CHAT_HEADER_SIZE 3
#define xstr(a) str(a)
#define str(a) #a

void sendToServer(int socketNum, uint8_t* sendBuf, int sendLen, int sendFlag);
void checkArgs(int argc, char * argv[]);

void attachChatHeader(uint8_t* sendBuf, uint16_t size, uint8_t flag) {
	uint16_t trueSize = htons(size + CHAT_HEADER_SIZE);
	sendBuf[0] = ((trueSize & 0xff00) >> 8);	// insert MSB
	sendBuf[1] = trueSize & 0x00ff;				// insert LSB
	sendBuf[2] = flag;
}

void initConnection(int socketNum, char** argv, uint8_t* sendBuf) {
	attachChatHeader(sendBuf, strlen(argv[1]) + CHAT_HEADER_SIZE, NEW_CLIENT);
	memcpy(sendBuf + CHAT_HEADER_SIZE, argv[1], strlen(argv[1]));
	sendToServer(socketNum, sendBuf, strlen(argv[1]), 0);
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

int setNumDestHandles(char* token, int* numDestHandles) {
	int startsWithNumber = 0;

	if (strlen(token) == 1) {
		if (isdigit(token[0])) { 
			*numDestHandles = atoi(token);
		}
		else {
			*numDestHandles = 1;
		}
	}
	else {
		if ( isdigit(token[0])) {
			startsWithNumber = 1;
		}

		// Must deal with case where user does not enter number of handles
		// if this is the case, the token in question IS the name of the destination
		// so we do not want to add any more entries to the token list
		*numDestHandles = 0;
	}
	return startsWithNumber;
}

void setNumMessages(int length, int* numMessages) {
	int textLen = length;
	while (textLen > 200) {
		*numMessages = *numMessages + 1;
		textLen -= 200;
	}
}

void sendMessageBuf(uint8_t* sendBuf, char** tokens, int numTokens, 
		uint16_t messageLength, char* text, int socketNum, uint8_t* thisHandle,
		int handLen) {

	int bufPos = CHAT_HEADER_SIZE;
	int i = 0;
	uint8_t tokLen = 0;

	bzero(sendBuf, MAXBUF);
	attachChatHeader(sendBuf, messageLength+handLen+strlen(text), (uint8_t)MESSAGE);

	// Attach Client's Handle Name
	sendBuf[bufPos++] = (uint8_t)handLen;
	memcpy(sendBuf + bufPos, thisHandle, handLen);
	bufPos += handLen;
	for (i = 0; i < numTokens; i++) {
		tokLen = strlen(tokens[i]);
		sendBuf[bufPos] = tokLen;
		memcpy(sendBuf+bufPos+1, tokens[i], tokLen);
		bufPos += tokLen+1;

		printf("\tClient side token: %s\n", tokens[i]);
	}

	// Now attach message
	memcpy(sendBuf+bufPos, text, strlen(text));
	sendBuf[bufPos+strlen(text)] = '\0';
	printf("Client: %s\n", text);
	sendToServer(socketNum, sendBuf, messageLength + handLen + strlen(text)+1, 0);
}

void sendMessage(uint8_t* sendBuf, char* input, int socketNum, uint8_t* thisHandle,
		int handLen) {
	uint16_t messageLength = 0;
	char* tokens[30], *text, subtext[200];
	int i = 0;
	int numTokens = 0, numDestHandles = 0;
	int numMessages = 1, textPos = 0, textLen = 0;

	bzero(sendBuf, MAXBUF);

	// Split input into %M tokens
	tokens[0] = strtok(input, " ");		// %M command
	tokens[1] = strtok(NULL, " ");		// either number of handles or a handle itself
	numTokens += 2;

	if (setNumDestHandles(tokens[1], &numDestHandles)) {
		printf("Invalid handle, handle starts with a number\n");
		return;
	}
	if (numDestHandles > 9) {
		printf("Please only enter up to 9 Handles\n");
		return;
	}

	// Let each handle have its own token -- do not split text message
	for (i = 0; i < numDestHandles; i++) {
		tokens[i+2] = strtok(NULL, " ");	// dont overwrite existing tokens
	}
	numTokens += numDestHandles;

	// Handle user Text Message
	text = strtok(NULL, "\0");		// the rest of the packet is the text message
	textLen = strlen(text);
	setNumMessages(textLen, &numMessages);
	messageLength = getPacketLength(tokens, numTokens) + textLen;

	for (i = 0; i < numMessages; i++){
		if (numMessages == 1) {
			memcpy(subtext, text, textLen);
		}
		else if (i == numMessages - 1) {
			memcpy(subtext, text+textPos, textLen);
		}
		else {
			memcpy(subtext, text+textPos, 200);
			textLen -= 200;
			textPos += 200;
		}
		sendMessageBuf(sendBuf, tokens, numTokens, messageLength, subtext, socketNum, thisHandle, handLen);
		bzero(subtext, 200);
	}
}

void parseCommand(char* input, uint8_t* sendBuf, int socketNum, uint8_t* thisHandle,
		int handLen) {
	int commandID = -1;
	char command[2];

	memcpy(command, input, 2);
	bzero(sendBuf, MAXBUF);
	commandID = parseID(command);
	switch (commandID) {
		case MESSAGE:
			printf("\tMessage command!\n");
			sendMessage(sendBuf, input, socketNum, thisHandle, handLen);
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

void run (int socketNum, uint8_t* sendBuf, uint8_t* thisHandle, int handLen) {
	char input[MAXBUF];
	//int sendLen = 0;        	// amount of data to send

	while (memcmp(sendBuf, "%E", 2) != 0 && memcmp(sendBuf, "%e", 2) != 0){
		bzero(input, MAXBUF);
		printf("$: ");
		scanf(" %" xstr(MAXBUF) "[^\n]%*[^\n]", input);
		parseCommand(input, sendBuf, socketNum, thisHandle, handLen);
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
	bzero(sendBuf, MAXBUF);
	memcpy(thisHandle, argv[1], strlen(argv[1]));
	run(socketNum, sendBuf, thisHandle, strlen(argv[1]));
	close(socketNum);
	
	return 0;
}

void sendToServer(int socketNum, uint8_t* sendBuf, int sendLen, int sendFlag)
{
	int sent = 0;	// actual amount of data sent

	sent = send(socketNum, sendBuf, sendLen+CHAT_HEADER_SIZE, 0);
	if (sent < 0)
	{
		perror("send call");
		exit(-1); 
	}
	printf("\tString sent: %s\n", sendBuf + CHAT_HEADER_SIZE);
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
