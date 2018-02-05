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
#define DEBUG_FLAG 1

void recvFromClient(int clientSocket, char* buf);
int checkArgs(int argc, char *argv[]);

typedef struct {
	int fd;
	char handle[100];
} Client;

void error(char* message) {
	printf("%s\n", message);
}

int checkExitCommand(char* buf, int* numClients, int clientSocket) {
	if (memcmp(buf, "%E", 2) != 0 && memcmp(buf, "%e", 2) != 0){
		return 0;
	}
	// Case client has quit
	close(clientSocket);		// close socket
	// free entry in handle array
	(* numClients) = (* numClients) - 1;
	return 1;
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

/* Checks to see if there is a new client connecting to the server */
void checkNewClient(int serverSocket, fd_set* fds, int* numClients, int* maxFd,
		Client* clients) {

	int clientSocket = 0;
	Client newClient;

	newClient.fd = 0;
	if (FD_ISSET(serverSocket, fds)){
		clientSocket = tcpAccept(serverSocket, DEBUG_FLAG); // get new client fd
		newClient.fd = clientSocket;
		memcpy(newClient.handle, "Bob", 3);
		clients[clientSocket] = newClient;
		(* numClients) = (* numClients) + 1;
		if (clientSocket > *maxFd) {
			*maxFd = clientSocket;
		}
	}
}

/* Checks to see if clients have any pending requests */
void checkClients(fd_set* fds, int* numClients, Client* clients, int* maxFd, 
		char* buf) {
	int clientSocket = 0;
	int i = 0;
	for(i = 3; i < *maxFd + 1; i++) {
		if (clients[i].fd == 0){
			continue;	
		}
		clientSocket = clients[i].fd;
		if (FD_ISSET(clientSocket, fds)) {
			recvFromClient(clientSocket, buf);
			checkExitCommand(buf, numClients, clientSocket);	
		}
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
void run(int serverSocket, int portNumber, char* buf, int* numClients, 
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

int main(int argc, char *argv[])
{
	int serverSocket = 0, portNumber = 0;
	int numClients = 0, maxFd = 0;
	char buf[MAXBUF];
	Client* clients = (Client* ) calloc(10, sizeof(Client));
	
	portNumber = checkArgs(argc, argv);			// get port number
	serverSocket = tcpServerSetup(portNumber);	// create server socket
	maxFd = serverSocket;
	run(serverSocket, portNumber, buf, &numClients, clients, &maxFd);	
	close(serverSocket);
	return 0;
}

void recvFromClient(int clientSocket, char* buf)
{
	int messageLen = 0;
	
	if ((messageLen = recv(clientSocket, buf, MAXBUF, 0)) < 0)
	{
		perror("recv call");
		exit(-1);
	}
	//now get the data from the client_socket
	printf("Message received, length: %d Data: %s\n", messageLen, buf);
	printf("Current contents of buf: %c%c\n", buf[0], buf[1]);
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

