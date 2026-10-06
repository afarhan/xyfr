#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/select.h>
#include <poll.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

int udp_socket_open(char *strAddress, uint16_t port) {
	struct sockaddr_in addr;
	int isock = -1;
  
  isock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);

	if (isock == -1)
	{
		printf("*Error:unable to create a socket. A copy of the server may already be running.");
		exit(1);   // hard failure — non-zero so a supervisor doesn't see a clean exit (M-9)
	}

	int	setOn=1;

	setsockopt(isock, SOL_SOCKET, SO_REUSEADDR, (char *)&setOn, sizeof(setOn));

	//if the port is not specifiied (=0), don't bind it to any port
	if (!port)
		return isock;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	if (!strAddress || !*strAddress || !strcmp(strAddress, "0.0.0.0"))
		addr.sin_addr.s_addr = htonl(INADDR_ANY);
	else
		addr.sin_addr.s_addr = inet_addr(strAddress);
		
	if (bind(isock, (struct sockaddr *) &addr, sizeof(addr)) != 0)
	{
		close(isock);
		isock = 0;
		printf("*Error:unable to bind the server socket.");
		exit(1);   // hard failure — non-zero exit (M-9)
	}
	return isock;
}

int udp_read(int sock, uint8_t *data, int max_length, uint32_t *ip, uint16_t *port) {	
	struct sockaddr_in	addr;
	int	ret;
	socklen_t	dummylen;

	// wait up to 1 millisecond for data using poll (handles large fds reliably)
	struct pollfd pfd;
	pfd.fd = sock;
	pfd.events = POLLIN;

	int pol = poll(&pfd, 1, 1); // timeout in ms
	if (pol <= 0) {
		// timeout (0) or error (-1)
		return -1;
	}

	if (!(pfd.revents & POLLIN)) {
		return -1;
	}

	dummylen = sizeof(addr);
	ret = recvfrom(sock, (void *)data, max_length, 0, (struct sockaddr *)&addr, &dummylen);

	if (ret > 0){
		*ip    = (uint32_t)addr.sin_addr.s_addr;
		*port  = ntohs(addr.sin_port);
	}

	return ret;
}

int udp_write(int sock, void *data, int length, uint32_t ip, uint16_t port) {
	struct sockaddr_in	addr;

	addr.sin_addr.s_addr = ip;
	addr.sin_port = (short)htons(port);
	addr.sin_family = AF_INET;

	return sendto(sock, data, length, 0, (struct sockaddr *)&addr, sizeof(addr));
}

const char *ip2string(uint32_t address) {
	struct in_addr	addr;

	addr.s_addr = address;
	return inet_ntoa(addr);
}

uint32_t string2ip(const char *host) {
	int i, count=0;
	const char *p = host;
	struct sockaddr_in	addr;
	struct hostent		*pent;


	if (strlen(host) > 16)
		return 0;

	while (*p)
	{
		for (i = 0; i < 3; i++, p++)
			if (!isdigit(*p))
				break;
		if (*p != '.')
			break;
		p++;
		count++;
	}

	if (count == 3 && i > 0 && i <= 3)
		return inet_addr(host);

	pent = gethostbyname(host);
	if (!pent)
		return 0;

	addr.sin_addr = *((struct in_addr *) *pent->h_addr_list);
	return addr.sin_addr.s_addr;
}

