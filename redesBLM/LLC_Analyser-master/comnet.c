#include "comnet.h"

int getData(int sd)
{
	struct ifreq nic;
	int index, i;
	char select, interface_name[10];

	printf("Elije la interfaz de red a utilizar\n 1.-enp2s0\n 2.-wlp3s0\n 3.-Salir\n -> ");
	scanf("%c", &select);

	switch (select)
	{
		case '1':
			strcpy(interface_name, "enp2s0");
			break;
		
		case '2':
			strcpy(interface_name, "wlp3s0");
			break;
	
		default:
		printf("Error al seleccionar la interfaz de red.\n");
			exit(1);
			break;
	}

	strcpy(nic.ifr_name, interface_name);

	/* obtener el indice de la interfaz de red */
	
	if(ioctl(sd, SIOCGIFINDEX, &nic) == -1)
	{
		perror("Error al obtener el indice\n");
		exit(1);
	}
	else
	{
		index = nic.ifr_ifindex;
	}

	/* obtener mi direccion MAC */

	if(ioctl(sd, SIOCGIFHWADDR, &nic ) == -1)
	{
		perror("Error al obtener la MAC\n");
		exit(1);
	}
    else
    {
		memcpy(my_MAC, nic.ifr_hwaddr.sa_data+0, 6);
		printf("Mi direccion MAC es: ");
		
		for( i = 0 ; i < 6 ; i++ )
		{
			if(i == 5)
				printf("%.2X\n", my_MAC[i]);
			else
				printf("%.2X:", my_MAC[i]);
		}
	}

	/* obtener mi direccion IP */

	if(ioctl(sd, SIOCGIFADDR, &nic) == -1)
	{
		perror("Error al obtener la dirección IP\n");
		exit(1);
	}
	else
	{
		memcpy(my_IP, nic.ifr_addr.sa_data+2, 4);
		printf("Mi direccion IP es: ");
		
		for( i = 0 ; i < 4 ; i++ ){
			if( i == 3 )
				printf("%d\n", my_IP[i]);
			else 
				printf("%d.", my_IP[i]);
		}
	}

	/* obtener mi mascara de subred */

	if(ioctl(sd, SIOCGIFNETMASK, &nic) == -1)
	{
		perror("Error al obtener la mascara de subred\n");
		exit(1);
	}
	else
	{
		memcpy(NETMASK, nic.ifr_netmask.sa_data+2, 4);
		printf("Mi mascara de subred es: ");
		
		for( i = 0 ; i < 4 ; i++ ){
			if( i == 3 )
				printf("%d\n", NETMASK[i]);
			else 
				printf("%d.", NETMASK[i]);
		}
	}

	/* obtener la metrica */

	if(ioctl(sd, SIOCGIFMETRIC, &nic) == -1)
	{
		perror("Error al obtener la metrica\n");
		exit(1);
	}
	else
	{
		Metric = nic.ifr_metric;
		printf("Mi metrica es: %d\n", Metric);
	}

	/* obtener el MTU */

	if(ioctl(sd, SIOCGIFMTU, &nic) == -1)
	{
		perror("Error al obtener el MTU\n");
		exit(1);
	}
	else
	{
		MTU = nic.ifr_mtu;
		printf("Mi MTU es: %d\n", MTU);
	}

	printf("\n");

	return index;
}
/*
void printFrame(unsigned char *frame, int size)
{
	int i;

	for( i = 0 ; i < size ; i++ )
	{
		if( i%16 == 0 )
			printf("\n");
		printf("%.2x ", frame[i]);
	}

	printf("\n");
}
*/
void receiveFrame(int sd, unsigned char *frame)
{
	int size, flag = 0;

	gettimeofday(&start, NULL);
	mtime = 0;
    
    while(mtime < 200){
		
		size = recvfrom(sd, frame, 1514, MSG_DONTWAIT, NULL, 0);

		if( size == -1 )
		{
			//perror("Error al recibir");
		}
		else
		{
			printFrame(frame, size);
		}
	
		gettimeofday(&end, NULL);

		seconds  = end.tv_sec  - start.tv_sec;
		useconds = end.tv_usec - start.tv_usec;

		mtime = ((seconds) * 1000 + useconds/1000.0) + 0.5;
		
		if( flag == 1 )
		{
			//printf("\nElapsed time: %ld milliseconds\n", mtime);
			break;
		}

	}

	if( flag == 0 ){
		//perror("Error al recibir");
		//printf("Elapsed time: %ld milliseconds\n", mtime);
	}

}