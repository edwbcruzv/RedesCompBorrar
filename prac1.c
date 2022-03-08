#include<sys/socket.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include<stdlib.h>
#include<unistd.h>
#include<stdio.h>
#include<arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
//recordar que  un entero es de de 4 bits
//IP es de 4 espacios, cada uno con 2bytes, entonces, serian de 8 bytes=32bits en total
//MAC es de 6 espacion, cada uno con 2 bytes, entonces, serian de 12 bytes=48bits en total
unsigned char IPorigen[4],MACorigen[6],MASCARAorigen[4];
unsigned char IPdestino[4],MACdestino[6];
//
unsigned char tramaEnv[1514],tramaRec[1514];
////Es como empieza la trama al enviarlo para que la comunicacion sea broadcast
unsigned char MACbroad[6]={0xff,0xff,0xff,0xff,0xff,0xff};
unsigned char ethertype[2]={0x08,0x06};
unsigned char hardware[2]={0x00,0x01},protocol[2]={0x08,0x00},codeARPenv[2]={0x00,0x01},codeARPrec[2]={0x00,0x02};


int obtenerDatos(int ds){

	int index;

	struct ifreq nic;
	printf("\nInserta el nombre\n");
	scanf("%s",nic.ifr_name);

	// obtener mac SIOCGIFHWADDR
	//obtener indice SIOCGIFINDEX


	///obteniendo el numero de indicede red-------------------------------------------
	if(ioctl(ds,SIOCGIFINDEX,&nic)==-1)
	{ perror("error al obtener el indice");
	  exit(1);
	}
	else{
		index=nic.ifr_ifindex;
		printf("indice obtenido\n");


		////obteniendo el numero MAC-----------------------------------------------
		if(ioctl(ds,SIOCGIFHWADDR,&nic)==-1)
		{ perror("error al obtener la mac");
	  		exit(1);
		}
		else{
			memcpy(MACorigen,nic.ifr_hwaddr.sa_data+0,6);
			for(int i=0;i<6;i++)
				printf("%.2x",MACorigen[i]);

			////obteniendo el numero ip---------------------------------------
			if(ioctl(ds,SIOCGIFADDR,&nic)==-1)
			{ perror("error al obtener la ip");
	  			exit(1);
			}
			else{
				printf("\nLa direccion ip es: ");
			memcpy(IPorigen,nic.ifr_hwaddr.sa_data+2,4);
			for(int i=0;i<4;i++)
				printf("%d",IPorigen[i]);

				///obteniendo la mascara de subred----------------------------
				if(ioctl(ds,SIOCGIFADDR,&nic)==-1)
				{ perror("error al obtener la ip");
	  				exit(1);
				}
				else{
					memcpy(MASCARAorigen,nic.ifr_addr.sa+2,4);
					for(i=0;i<4;i++)
						printf("%d",MASCARAorigen[i]);
				}


			}

		}

	}
	return index;
}


void EstructuraTrama(unsigned char* trama){
	memcpy(trama+0,MACbroad,6);
	memcpy(trama+6,MACorigen,6);
	memcpy(trama+12,ethertype,2);
	memcpy(trama+14,hardware,2);
	memcpy(trama+16,protocol,2);
	trama[18]=6;
	trama[19]=4;
	memcpy(trama+20,codeARPenv,2);
	memcpy(trama+22,MACorigen,6);
	memcpy(trama+28,IPorigen,4);
	memcpy(trama+28,0x00,6);
	memcpy(trama+28,IPdestino,4);

}

void ImprimeTrama(unsigned char* paq,int len){
	int i;
	for(i=0;i<len;i++){
		if(i%16==0)
			printf("\n");

		printf("%.2x ",paq[i]);
	}
	printf("\n");
}
/*
*La estructura sockaddr_ll es una capa física independiente del dispositivo.
*			habla a.
*
*					struct sockaddr_ll {
*							unsigned short sll_family; / * Siempre AF_PACKET * /
*							unsigned short sll_protocol; / * Protocolo de capa física * /
*							int sll_ifindex; / * Número de interfaz * /
*							unsigned short sll_hatype; / * Tipo de hardware ARP * /
*							unsigned char sll_pkttype; / * Tipo de paquete * /
*							unsigned char sll_halen; / * Longitud de la dirección * /
*							unsigned char sll_addr [8]; / * Dirección de capa física * /
*					};
*/

void EnviarTrama(int ds, int index,unsigned char*trama){
	int tam;
	//declarando socket para 
	struct sockaddr_ll nic;
	memset(&nic,0x00,sizeof(nic));
	nic.sll_family=AF_PACKET;
	nic.sll_protocol=htons(ETH_P_ALL);
	nic.sll_ifindex=index;
	//ImprimeTrama(trama,60);
	tam=sendto(ds,trama,60,0,(struct sockaddr*)&nic,sizeof(nic));

	if(tam==-1){
			perror("\nerror al enviar");
			exit(1);
	}
	else printf("exito al abrir");

}

void RecibeTrama(int ds,unsigned char* trama){
	int tam,bandera=0;
	struct timeval start, end;

    long mtime=0, seconds, useconds;

    gettimeofday(&start, NULL);
    while(mtime<1000){
	tam=recvfrom(ds,trama,1514,MSG_DONTWAIT,NULL,0);

	if(tam==-1){
			perror("\nError al recibir");
			exit(1);
	}
	else{
		if(!memcmp(trama+0,MACorigen,6)){
			ImprimeTrama(trama,tam);
			bandera=1;
			}
		gettimeofday(&end, NULL);
		seconds  = end.tv_sec  - start.tv_sec;
   		useconds = end.tv_usec - start.tv_usec;
		mtime = ((seconds) * 1000 + useconds/1000.0) + 0.5;
		if(bandera==1)
			break;
		}
	printf("Elapsed time: %ld milliseconds\n", mtime);
	}
}



int main(){

	int packet_socket,indice;

	packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if(packet_socket==-1){
		perror("Error al abrir el Socket");
		exit(1);
	}
	else{
		perror("Exito al abrir el Socket");
		//meterobteneripdestino
		indice=obtenerDatos(packet_socket);
		printf("\nEl indice es: %d\n\n",indice);
		EstructuraTrama(tramaEnv);
		EnviarTrama(packet_socket,indice,tramaEnv);
		RecibeTrama(packet_socket,tramaREC);
	}
	for(i=0;i<6;i++)
		printf("%.2x",MACdestino[i]);

	close(socket_packet)



	close(packet_socket);

	return 0;

}
