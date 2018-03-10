/* network code - UDP - written by Hugh Smith */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "networks.h"
#include "cpe464.h"

int32_t udp_server(int portNumber)
{
	int sk = 0;						// socket descriptor
	struct sockaddr_in local;		// socket address for us
	uint32_t len = sizeof(local);	// length of local address


	// create the socket
	if ((sk = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		perror("socket");
		exit(-1);
	}

	// set up socket
	local.sin_family = AF_INET;				// internet family
	local.sin_addr.s_addr = INADDR_ANY;		// wild card machine address
	local.sin_port = htons(portNumber);		// let system choose port

	// bind the name (address) to a port
	if (bindMod(sk, (struct sockaddr *)&local, sizeof(local)) < 0)
	{
		perror("udp_server, bind");
		exit(-1);
	}

	// get the port name and print32_t it out
	getsockname(sk, (struct sockaddr *)&local, &len);
	printf("Using Port #: %d\n", ntohs(local.sin_port));

	return(sk);
}

/* returns pointer to a sockaddr_in that it created or NULL if host not found */
/* also passes back the socket number in sk */
int32_t udp_client_setup(char * hostname, uint16_t port_num, Connection * connection) 
{
	struct hostent * hp = NULL;		// address of remote host

	connection->sk_num = 0;
	connection->len = sizeof(struct sockaddr_in);

	//create the scoket
	if ((connection->sk_num = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		perror("udp_client_setup, socket");
		exit(-1);
	}

	// designate the addressing family
	connection->remote.sin_family = AF_INET;

	// get the address of the remote host and store
	hp = gethostbyname(hostname);

	if (hp == NULL)
	{
		printf("Host not found: %s\n", hostname);
		return -1;
	}

	memcpy(&(connection->remote.sin_addr),hp->h_addr,hp->h_length);

	// get the port used on the remote side and store
	connection->remote.sin_port = htons(port_num);

	return 0;

}

int32_t select_call(int32_t socket_num, int32_t seconds, int32_t microseconds, int32_t set_null)
{
	fd_set fdvar;
	struct timeval aTimeout;
	struct timeval * timeout = NULL;

	if (set_null == NOT_NULL)
	{
		aTimeout.tv_sec = seconds;			// set timeout to 1 sec
		aTimeout.tv_usec = microseconds;	// timeout (in micro-second)
		timeout = &aTimeout;
	}

	FD_ZERO(&fdvar);	// reset variables
	FD_SET(socket_num, &fdvar);

	if (select(socket_num+1, (fd_set *)&fdvar, (fd_set *)0, (fd_set *)0, timeout) < 0)
	{
		perror("select");
		exit(-1);
	}

	if (FD_ISSET(socket_num, &fdvar))
	{
		return 1;
	} else
	{
		return 0;
	}

}

int32_t safeSend(uint8_t * packet, uint32_t len, Connection * connection) 
{
	int send_len = 0;
	if ((send_len = sendtoErr(connection->sk_num, packet, len, 0,
			(struct sockaddr *)&(connection->remote), connection->len)) < 0)
	{
		perror("in send_buf(), sendto() call");
		exit(-1);

	}

	return send_len;
}
























