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






void EstructuraARPsol(unsigned char*);
void EnviarTrama(int,int,unsigned char*);



unsigned char tramaARPsol[60]={0xff,0xff,0xff,0xff,0xff,0xff,
							  0x00,0x00,0x00,0x00,0x00,0x00,0x08,0x06,
							  0x00,0x01,0x08,0x00,0x06,0x04,0x00,0x01,
							  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
							  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
							  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
							  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
							  0x00,0x00,'E','B','C','V'};


int main(){
	int packet_socket,indice;
	
	
	packet_socket=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
	
	if(packet_socket==-1){
		perror("Error al abrir el Socket");
		exit(1);
	}
	else{
		perror("Exito al abrir el Socket");
		
		indice=ObtenerDatos(packet_socket);
		
		obtenerIPDestino();
		
		EstructuraARPsol(tramaARPsol);
		
		printf("\nLa trama que se envia es: ");
		
		ImprimeTrama(tramaARPsol,60);
		
		EnviaTrama(packet_socket,indice,tramaARPsol);
		
	}
	
	close(packet_socket);
	return 1;
}



void EstructuraARPsol(unsigned char* trama){
	//Encabezado MAC
	
	memcpy(trama+6,MACorigen,6);
	
	//Mensaje de arp
	
	memcpy(trama+22,MACorigen,6);
	memcpy(trama+28,IPorigen,6);
	memcpy(trama+32,0x00,6);
	memcpy(trama+38,IPdestino,6);
}

void EnviarTrama(int ds,in index,unsigned char* paq){
	int tam;
	
	struct sockaddr_ll capaEnlace;
	
	memset(&capaEnlace,0x00,sizeof(capaEnlace));
	
	capaEnlace.sll_family=AF_PACKET;
	capaEnlace.sll_protocol=htons(ETH_P_ALL);
	capaEnlace.sll_ifindex=index;
	
	tam=sendto(ds,paq,60,0,(struct sockaddr*)&capaEnlace,sizeof(capaEnlace));
	
	if(tam==-1){
			perror("\nerror al enviar trama");
			exit(1);
	}
	else printf("exito al enviar trama");
}
