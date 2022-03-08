 #include <sys/socket.h>
 #include <netinet/in.h>
 #include <netinet/ip.h> /* superset of previous */
 #include<stdio.h>
 #include<string.h>
 #include<stdlib.h>
 #include<unistd.h>
 #include <arpa/inet.h>

int main(){
	struct sockaddr_in servidor,cliente;
	unsigned char paq[60]="";
	
	int udp_socket,lbind,tam,lreciv;
	udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
	
	if(udp_socket==-1){//se comprueba que no exista un error
		perror("\nNo funciono el socket ");
		exit(1);
	
	}
	else {
		memset(&servidor,0x00,sizeof(servidor));
		
		servidor.sin_family=AF_INET;
		servidor.sin_port=htons(8080);
		servidor.sin_addr.s_addr=INADDR_ANY;
		
		lbind=bind(udp_socket,(struct sockaddr*)&servidor,sizeof(servidor));
		if(lbind==-1){
			perror("\nError en el servidor");
			exit(1);
			
		}
		
		perror("\nExito al abrir el servidor");
		//-----------------------------------------------------
	
		lreciv=sizeof(cliente);
	
		while(1){
			tam=recvfrom(udp_socket,paq,60,0,(struct sockaddr*)&cliente,&lreciv);
			if(tam==-1){
				perror("\nError al recibir");
				exit(1);
			}
			else{
				printf(":%s\n",paq);
			}
		}
			
	}	
	
	close(udp_socket);
	
	
	
	
	return 0;
		
}