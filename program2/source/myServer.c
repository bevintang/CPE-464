/******************************************************************************
* tcp_server.c
*
* CPE 464 - Program 1
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
#define MESSAGE 5	// flag = 5
#define LIST 10		// flag = 10
#define EXIT 8		// flag = 8
#define NEW_CLIENT 69
#define DEBUG_FLAG 1 

typedef struct {
	int fd;
	char handle[100];
} Client;

void recvFromClient(Client* clients, int clientSocket, uint8_t* buf);
int checkArgs(int argc, char *argv[]);

void error(char* message) {
	printf("%s\n", message);
}

/* Sets the fd of the set where clients occupy the corresponding socket number */
void setClients(fd_set* fds, int* numClients, Client* clients, int* maxFd) {
	int clientSocket = 0;
	int i = 0;
	for(i = 3; i < *maxFd+1; i++) {
		if (clients[i].fd != 0){
			clientSocket = clients[i].fd;
			FD_SET(clientSocket, fds);
		}
	}
}

void addNewClient(int clientSocket, Client* clients, int* numClients, int* maxFd) {
	Client newClient;

	// Intialize values
	newClient.fd = clientSocket;
	memcpy(newClient.handle, "Bob", 3);
	clients[clientSocket] = newClient;
	printf("Added new client at socket: %d\n", clientSocket);
	(* numClients) = (* numClients) + 1;

	// Check if there is a new maxFd
	if (clientSocket > *maxFd) {
		*maxFd = clientSocket;
	 }
}

/* Checks to see if there is a new client connecting to the server */
void checkNewClient(int serverSocket, fd_set* fds, int* numClients, int* maxFd,
		Client* clients) {

	int clientSocket = 0;

	if (FD_ISSET(serverSocket, fds)){
		clientSocket = tcpAccept(serverSocket, DEBUG_FLAG); // get new client fd
		addNewClient(clientSocket, clients, numClients, maxFd);
	}
}

int checkExitCommand(uint8_t* buf, int* numClients, int clientSocket, Client* clients) {
	Client nullClient;

	if (memcmp(buf, "%E", 2) != 0 && memcmp(buf, "%e", 2) != 0){
		return 0;
	}
	// Case client has quit
	nullClient.fd = 0;
	clients[clientSocket] = nullClient;	// free entry in handle array
	(* numClients) = (* numClients) - 1;
	close(clientSocket);
	printf("\tClient at socket %d closed\n", clientSocket);
	return 1;
}

void setName (Client* clients, int clientSocket, uint8_t* buf) {
	uint16_t nameSize = ntohs(( ((uint16_t)buf[0] << 8) | buf[1])) - 3;
	memcpy(clients[clientSocket].handle, buf+3, nameSize);
	printf("Client at socket %d's name set to %s\n", clientSocket, clients[clientSocket].handle);
}

void parseCommand(Client* clients, int clientSocket, uint8_t* buf) {
	uint8_t commandID = buf[2];

	switch (commandID) {
		case MESSAGE:
			printf("\tIncoming Message!\n");
			break;
		case LIST:
			printf("\tClient Requests List of handles!\n");
			break;
		case EXIT:
			printf("\tClient wants to exit!\n");
			break;
		case NEW_CLIENT:
			printf("\tNew client!\n");
			setName(clients, clientSocket, buf);
			break;
	}
}

void recvFromClient(Client* clients, int clientSocket, uint8_t* buf)
{
	int messageLen = 0;
	
	bzero(buf, MAXBUF);
	if ((messageLen = recv(clientSocket, buf, MAXBUF, 0)) < 0)
	{
		perror("recv call");
		exit(-1);
	}

	parseCommand(clients, clientSocket, buf);

	// Display buffer contents
	printf("Message received, length: %d Data: %s\n", messageLen, buf+3);
}

void recvRequest(int clientSocket, fd_set* fds, uint8_t* buf, int* numClients,
		Client* clients) {

	if (FD_ISSET(clientSocket, fds)) {
		bzero(buf, MAXBUF);
		recvFromClient(clients, clientSocket, buf);
		checkExitCommand(buf, numClients, clientSocket, clients);	
	}
}

/* Checks to see if clients have any pending requests */
void checkClients(fd_set* fds, int* numClients, Client* clients, int* maxFd, 
		uint8_t* buf) {
	int clientSocket = 0;
	int i = 0;
	for(i = 3; i < *maxFd + 1; i++) {
		if (clients[i].fd == 0){
			continue;	
		}
		clientSocket = clients[i].fd;
		recvRequest(clientSocket, fds, buf, numClients, clients);
	}
}

/* Main Functionality of Server.
	Loop{
		1) zero fd_set
		2) set server socket
		3) set client sockets
		4) select fd_set sockets
		5) look for new clients
		6) check for client requests
	} */
void run(int serverSocket, int portNumber, uint8_t* buf, int* numClients, 
		Client* clients, int* maxFd) {
	fd_set fds;

	while (1) {
		FD_ZERO(&fds);
		FD_SET(serverSocket, &fds);
		setClients(&fds, numClients, clients, maxFd); 

		select(*maxFd + 1, &fds, NULL, NULL, NULL);

		checkNewClient(serverSocket, &fds, numClients, maxFd, clients);
		checkClients(&fds, numClients, clients, maxFd, buf);
	}
}

int checkArgs(int argc, char *argv[])
{
	// Checks args and returns port number
	int portNumber = 0;

	if (argc > 2)
	{
		fprintf(stderr, "Usage %s [optional port number]\n", argv[0]);
		exit(-1);
	}
	
	if (argc == 2)
	{
		portNumber = atoi(argv[1]);
	}
	
	return portNumber;
}

int main(int argc, char *argv[])
{
	int serverSocket = 0, portNumber = 0;
	int numClients = 0, maxFd = 0;
	uint8_t buf[MAXBUF];
	Client* clients = (Client* ) calloc(10, sizeof(Client));
	
	portNumber = checkArgs(argc, argv);			// get port number
	serverSocket = tcpServerSetup(portNumber);	// create server socket
	maxFd = serverSocket;
	run(serverSocket, portNumber, buf, &numClients, clients, &maxFd);	
	close(serverSocket);
	return 0;
}
