 #include <sys/socket.h>
 #include <netinet/in.h>
 #include <netinet/ip.h> /* superset of previous */
 #include<stdio.h>
 #include<string.h>
 #include<stdlib.h>
 #include<unistd.h>
 #include <arpa/inet.h>

int main(){
	struct sockaddr_in local,remota;
	
	
	unsigned char paq[60]="algo mas amigable";
	
	int udp_socket,lbind,tam;
	udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
	
	if(udp_socket==-1){//se comprueba que no exista un error
		perror("\nNo funciono el socket ");
		exit(1);
	
	}
	else {
		memset(&local,0x00,sizeof(local));
		
		local.sin_family=AF_INET;
		local.sin_port=htons(0);
		local.sin_addr.s_addr=INADDR_ANY;
		lbind=bind(udp_socket,(struct sockaddr*)&local,sizeof(local));
		
		if(lbind==-1){
			perror("\nError en el blind");
			exit(1);
			
		}
		
		perror("\nExito al abrir el blind");
		//-----------------------------------------------------
		
		memset(&remota,0x00,sizeof(remota));

		remota.sin_family=AF_INET;
		remota.sin_port=htons(8080);
		remota.sin_addr.s_addr=inet_addr("10.100.79.183");
		
		
	while(1){	
		
		printf("\nEscribir mensaje: ");
		scanf("%s",paq);
			
		tam=sendto(udp_socket,paq,60,0,(struct sockaddr*)&remota,sizeof(remota));
		
		if(tam==-1){
			perror("\nError al enviar");
			exit(1);
		}
		else{
	
			perror("Exito al enviar");
			
			
		}
		
		
		
	}
		
	}
	close(udp_socket);
	
	
	
	
	return 0;
		
}