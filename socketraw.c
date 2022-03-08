#include <sys/socket.h>
#include <sys/time.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include<stdlib.h>
#include<unistd.h>
#include<stdio.h>
#include<arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>


unsigned char MACorigen[6];
unsigned char IPorigen[6];
unsigned char tramaEnv[1514],tramaREC[1514];
unsigned char MACbroad[6]={0xff,0xff,0xff,0xff,0xff,0xff};
unsigned char ethertype[2]={0x0c,0x0c};

int obtenerDatos(int ds){
	
	int index;
	
	struct ifreq nic;
	printf("\nInserta el nombre\n");
	scanf("%s",nic.ifr_name);
	
	// obtener mac SIOCGIFHWADDR
	//obtener indice SIOCGIFINDEX
	
	
	///obteniendo el numero de indice-------------------------------------------
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
			
			////obteniendo el nuemro ip---------------------------------------
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
				
				
			}
		
		}
	return index;
	}
}


void EstructuraTrama(unsigned char* trama){
	memcpy(trama+0,MACbroad,6);
	memcpy(trama+6,MACorigen,6);
	memcpy(trama+12,MACbroad,2);
	memcpy(trama+14,"algun pinche problema?",40);
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

void EnviarTrama(int ds, int index,unsigned char*trama){
	int tam;
	struct sockaddr_ll nic;
	memset(&nic,0x00,sizeof(nic));
	nic.sll_family=AF_PACKET;
	nic.sll_protocol=htons(ETH_P_ALL);
	nic.sll_ifindex=2;
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
		indice=obtenerDatos(packet_socket);
		printf("\nEl indice es: %d\n\n",indice);
	//	EstructuraTrama(tramaEnv);
	//	EnviarTrama(packet_socket,indice,tramaEnv);
		RecibeTrama(packet_socket,tramaREC);
	}
	
	close(packet_socket);
						   
	return 0;

}