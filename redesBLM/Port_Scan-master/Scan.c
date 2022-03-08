#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdlib.h>
#include <errno.h>

int main(int argc, char **argv)
{
	int sd;						 //descriptor de socket
	int port;					 //numero de puerto
	int start;					 //puerto inicial
	int end;					 //puerto final
	int rval;					 //sd para coneccion
	char responce[1024];		 //recibir datos
	char *message = "shell";	 //datos a enviar
	struct hostent *hostaddr;	 //IPAddress
	struct sockaddr_in servaddr; //socket

	if (argc < 4)
		return 0;

	start = atoi(argv[2]);
	end = atoi(argv[3]);
	int flag = 0;

sd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP); //socket TCP
		if (sd == -1)
		{
			perror("Socket()\n");
			return (errno);
		}

	for (port = start; port <= end; port++)
	{
		memset(&servaddr, 0, sizeof(servaddr));

		servaddr.sin_family = AF_INET;
		servaddr.sin_port = htons(port);

		hostaddr = gethostbyname(argv[1]);

		memcpy(&servaddr.sin_addr, hostaddr->h_addr, hostaddr->h_length);

		rval = connect(sd, (struct sockaddr *)&servaddr, sizeof(servaddr));
		if (rval == -1)
			flag++;
		else
			printf("Puerto %d abierto\n", port);
	}

	printf("Hay %d puertos cerrados\n", flag);

	close(sd);
}