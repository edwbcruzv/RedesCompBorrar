#include <sys/socket.h> 
#include <netpacket/packet.h>
#include <net/ethernet.h> 
#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <linux/netlink.h>
#include <asm/types.h>
#include <netinet/in.h>
#include <sys/time.h>

//Colores para imprimir en stdout.
#define RED   "\x1B[31m"
#define GRN   "\x1B[32m"
#define YEL   "\x1B[33m"
#define RESET "\x1B[0m"
#define MAG   "\x1B[35m"
#define CYN   "\x1B[36m"
#define BLU   "\x1B[34m"
#define TRAMA_LEN 42
#define IP_LEN 17
int abrirSocketRaw(void);
int obtenerDatos(int, struct ifreq *, unsigned char *, unsigned char *, unsigned char *, unsigned char *);
void imprimeTrama (unsigned char *, int);
void recibeTrama(unsigned char *, int, unsigned char *, struct in_addr*);
void enviarTrama (unsigned char *, int, int, int);
void estructuraTrama (unsigned char *, unsigned char *, unsigned char *, unsigned char *, unsigned char *, unsigned char *, unsigned char *, unsigned char *, unsigned char *, unsigned char *, struct in_addr *);
int obtenerIPdestino (struct in_addr *, int);
char obtenerNetType (unsigned char *);
int generarIPdestino (unsigned char *ownIP, struct in_addr *ptrIPDest, int octeto4, int octeto3, int octeto2);

int 
abrirSocketRaw(void)
{
int packet_socket = 0;
packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
if(packet_socket == -1){
	perror("Error al abrir el socket");
	exit (EXIT_FAILURE);
}
return packet_socket; 
}

int 
obtenerDatos(int ds, struct ifreq * ptrInterfaz, unsigned char * ownMAC, unsigned char * ownIP, unsigned char * ownBroadcast,  unsigned char * ownNetMask)
{
int index=0;
unsigned char IPorigenAsString[17], MACorigenAsString[18];
char stringToInsert[1024];
printf("Interfaz de red >> "YEL);
scanf("%s", ptrInterfaz->ifr_name);
printf(RESET);
if(ioctl (ds, SIOCGIFINDEX, ptrInterfaz) == -1)
	{
	perror("Error al obtener el índice");
	exit (EXIT_FAILURE);
	}
else
	{
	index = ptrInterfaz->ifr_ifindex;
    printf ("Índice >> "YEL"%d\n", index);
    printf(RESET);
	}
if (ioctl (ds, SIOCGIFHWADDR, ptrInterfaz) == -1)
    {
      perror ("Error al obtener la dirección MAC");
      exit (EXIT_FAILURE);
    }
else
    {
      memcpy (ownMAC, ptrInterfaz->ifr_hwaddr.sa_data, 6);
      printf ("Dirección MAC >> "YEL);
      fprintf(stdout, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", ownMAC[0], ownMAC[1], ownMAC[2], ownMAC[3], ownMAC[4], ownMAC[5]);
      printf(RESET);
    }	
if (ioctl (ds, SIOCGIFADDR, ptrInterfaz) == -1)
    {
      perror ("Error al obtener la dirección IP");
      exit (EXIT_FAILURE);
    }
else
    {
      memcpy (ownIP, ptrInterfaz->ifr_addr.sa_data + 2, 4);
      printf ("IPv4 >> "YEL);
      fprintf(stdout, "%d.%d.%d.%d\n", ownIP[0], ownIP[1], ownIP[2], ownIP[3]);
      printf(RESET);
    }
if (ioctl (ds, SIOCGIFBRDADDR, ptrInterfaz) == -1)
    {
      perror ("Error al obtener la broadcast");
      exit (EXIT_FAILURE);
    }
else
    {
     memcpy (ownBroadcast, ptrInterfaz->ifr_broadaddr.sa_data + 2, 4);
     printf ("Dirección de broadcast >> "YEL);
     fprintf(stdout, "%d.%d.%d.%d\n", ownBroadcast[0], ownBroadcast[1], ownBroadcast[2], ownBroadcast[3]);
     printf(RESET);
    }
if (ioctl (ds, SIOCGIFNETMASK, ptrInterfaz) == -1)
    {
      perror ("Error al obtener la mascara");
      exit (EXIT_FAILURE);
    }
else
    {
      memcpy (ownNetMask, ptrInterfaz->ifr_netmask.sa_data + 2, 4);
      printf ("Máscara de subred >> "YEL);
      fprintf(stdout, "%d.%d.%d.%d", ownNetMask[0], ownNetMask[1], ownNetMask[2], ownNetMask[3]);
      printf(RESET);
    }  
  printf ("\n");  

return index;
}

void
imprimeTrama (unsigned char *trama, int tramalen)
{
  int i;
  for (i = 0; i < tramalen; i++)
    {
        if (i % 16 == 0)
        printf ("\n");
      printf ("%.2x ", *(trama + i));

    }
  printf ("\n");
}	

void recibeTrama(unsigned char * trama, int ds, unsigned char *MACorigen, struct in_addr *ptrTPA){
int tam = 0, bandera = 0;
unsigned char replyIP[4], replyMAC[6];
unsigned char replyIPas_string[17], replyMACas_string[18];
char string_query[100];
struct timeval start, end;
long mtime =0, seconds, useconds;
unsigned char ethtype[2]={0x08,0x06};//Ethertype personalizado para identificar el paquete
unsigned char opcode[2]={0x00,0x02};//Reply

gettimeofday(&start, NULL);
while(mtime<300){

	tam=recvfrom(ds, trama, 1514, MSG_DONTWAIT, NULL, 0);
		
	if(!memcmp (trama + 0, MACorigen, 6)
       && !memcmp (trama + 12, ethtype, 2)
       && !memcmp (trama + 20, opcode, 2)
       && !memcmp (trama + 28, &ptrTPA->s_addr, 4)
       && !memcmp (trama + 32, MACorigen, 6))/*FILTRO >> solo imprimirá la trama que venga a mi MAC en dirección destino, ethtype 0806 
       el código de operacion 0002 (reply), que venga la IP por la que pregunté y mi MAC en Target Hardware Address*/
		{
      memset(&replyMAC, 0x00, 6);
      memset(&replyIP, 0x00, 4);
      memset(&replyIPas_string, 0x00, 17);
      memset(&replyMACas_string, 0x00, 18);
      memcpy(replyMAC, trama + 22, 6);
      memcpy(replyIP, trama + 28, 4);
		printf (GRN"\n\tTrama recibida\n");
		imprimeTrama(trama, tam);//Imprime la trama con ethtype 0xaeae y cierra el ciclo.
      printf (YEL "\nMAC: ");
      printf ("%s", replyMACas_string);
      printf (" | IP: ");
      printf ("%s", replyIPas_string);
      printf (RESET);
      bandera = 1;
      printf ("\n");
      printf ("\n" RESET);
		}

	
gettimeofday(&end, NULL);
seconds = end.tv_sec - start.tv_sec;
useconds = end.tv_usec - start.tv_usec;
mtime = ((seconds)*1000 + useconds/1000.0) + 0.5;
	if(bandera==1)
	break;
}
 printf (MAG "Elapsed time: %ld milliseconds", mtime);
 if(bandera==1){
 	printf(GRN" (Succes!)");
 }
  if (bandera == 0)
    {
      printf (RED " (Sin respuesta)");
    }
 printf ("\n");
 printf (RESET);
}

void
enviarTrama (unsigned char *trama_enviar, int tramalen, int ds, int index)
{
  int tam;
  struct sockaddr_ll interfaz;
  memset (&interfaz, 0x00, sizeof (interfaz));  //seteamos la interfaz a cero
  interfaz.sll_family = AF_PACKET;
  interfaz.sll_protocol = htons (ETH_P_ALL);
  interfaz.sll_ifindex = index;
  tam =
    sendto (ds, trama_enviar, tramalen, 0, (struct sockaddr *) &interfaz,
      sizeof (interfaz));
  if (tam == -1)
      perror ("No pude enviar la trama");


}

void
estructuraTrama (unsigned char *trama, unsigned char *MACdestino,
     unsigned char *MACorigen, unsigned char *ethtype,
     unsigned char *HWtype, unsigned char *PRtype, unsigned char *HAddrlen,
     unsigned char *PAddrlen, unsigned char *OPcode,
     unsigned char *IPOrigen, struct in_addr *ptrTargetProtocolAddress)
{
  memset(trama, 0x00, sizeof(trama)/sizeof(trama[0]));
  memcpy (trama + 0, MACdestino, 6);  //Direccion Destino (6 bytes)
  memcpy (trama + 6, MACorigen, 6); //Direccion Origen (6 bytes)
  memcpy (trama + 12, ethtype, 2);  //Ethertype (2 bytes)
  //Encabezado ARP.
  memcpy (trama + 14, HWtype, 2); //Hardware type
  memcpy (trama + 16, PRtype, 2); //Protocol type
  memcpy (trama + 18, HAddrlen, 1);//Hardware address length
  memcpy (trama + 19, PAddrlen, 1);//Protocol Address length
  memcpy (trama + 20, OPcode, 2);//Operation Code
  memcpy (trama + 22, MACorigen, 6);  //Source Hardware Address
  memcpy (trama + 28, IPOrigen, 4); //Source Protocol Address
  memset (trama+32, 0x00, 6);// Target Harware Address
  memcpy (trama + 38, &ptrTargetProtocolAddress->s_addr, 4); //Target Protocol Address
}

int
obtenerIPdestino (struct in_addr *ptrIPDestino, int ds)
{
unsigned char IPstringNumberAndDots[17];
  printf (CYN"\n(Ingresa \"0\" para salir) IP objetivo >> "RESET);
  scanf("%s", IPstringNumberAndDots);  
  if (strcmp (IPstringNumberAndDots, "0") == 0)
    {
      printf(BLU"\nBye\n"RESET);
      close (ds);
      exit (EXIT_SUCCESS);
    }
  else if (0 == inet_aton (IPstringNumberAndDots, ptrIPDestino))
    {
      fprintf(stderr, "¡Dirección IP inválida!\n");
      return -1;
    }
  else
    {
      return 1;     //Si retorna un int 1 significa que obtuvo correctamente la IP destino.
    }
}

char
obtenerNetType (unsigned char *MascaraDeRed)
{//Se trabajará solo con tipo C y con redes no subneteadas.
  if (MascaraDeRed[3] == 0 && MascaraDeRed[2] == 0 && MascaraDeRed[1] == 0)
    return 'a';
  else if (MascaraDeRed[3] == 0
     && MascaraDeRed[2] == 0 /*&& MascaraDeRed[1] != 255 */ )
    return 'b';
  else if (MascaraDeRed[3] ==0 /* && MascaraDeRed[2] != 255 && MascaraDeRed[1] != 255 */ )
    return 'c';
  else
    return -1;
}

int
generarIPdestino (unsigned char *ownIP, struct in_addr *ptrIPDest, int octeto4, int octeto3,
      int octeto2)
{
unsigned char IPstringNumberAndDots[17];
  if (octeto2 == -1 && octeto3 == -1) //tipo C
    sprintf (IPstringNumberAndDots, "%d.%d.%d.%d", (unsigned char) ownIP[0],
       (unsigned char) ownIP[1], (unsigned char) ownIP[2],
       (unsigned char) octeto4);
  else if (octeto2 == -1) //tipo b
    sprintf (IPstringNumberAndDots, "%d.%d.%d.%d", (unsigned char) ownIP[0],
       (unsigned char) ownIP[1], (unsigned char) octeto3,
       (unsigned char) octeto4);
  else
    {       //tipo a
      sprintf (IPstringNumberAndDots, "%d.%d.%d.%d", (unsigned char) ownIP[0],
         (unsigned char) octeto2, (unsigned char) octeto3,
         (unsigned char) octeto4);
    }
  if (0 == inet_aton (IPstringNumberAndDots, ptrIPDest))
    {
      fprintf(stderr, "¡Dirección IP inválida!\n");
      return -1;
    }
  else
    {
      printf (YEL "IP:%s", IPstringNumberAndDots);
      printf (RESET);
      printf (" | ");
      return 1; //Si retorna un int 1 significa que generó correctamente la IP destino.
    }
}

int main (void){
int ds, indice = 0, OC4;
unsigned char ownMAC[6], ownIP[4], ownBroadcast[4], ownNetMask[4];
struct ifreq Interfaz;
struct in_addr IPDestino;
unsigned char trama_recibir[1514], trama_enviar[1514];
//Elementos de la trama ARP.
unsigned char MACBroadcast[6]={0xff,0xff,0xff,0xff,0xff,0xff};
unsigned char EtherType[2]={0x08,0x06};
unsigned char HW[2]={0x00,0x01};
unsigned char PR[2]={0x08,0x00};
unsigned char HAlen=0x06, PAlen=0x04;
unsigned char OpCode[2]={0x00,0x01}; //Request

ds=abrirSocketRaw();
indice=obtenerDatos(ds, &Interfaz, ownMAC, ownIP, ownBroadcast, ownNetMask);

if(-1 == obtenerNetType(ownNetMask)){
  printf ("Error: Máscara de red subneteada.\n");
  exit(EXIT_FAILURE);
}

switch(obtenerNetType(ownNetMask)){
  case 'c':
      for(OC4=1; OC4<255; OC4++){
        if(generarIPdestino (ownIP, &IPDestino, OC4, -1, -1) == -1)
          exit(EXIT_FAILURE);
        else{
        estructuraTrama (trama_enviar, MACBroadcast, ownMAC, EtherType, HW, PR, &HAlen, &PAlen, OpCode, ownIP, &IPDestino);
        enviarTrama (trama_enviar, TRAMA_LEN, ds, indice);
        recibeTrama(trama_recibir, ds, ownMAC, &IPDestino);
        }
      }
    break;
  case 'b':
  /*FALTA CODIGO PARA CLASE B*/
    break;
  case 'a':
  /*FALTA CODIGO PARA CLASE A*/
    break;
  default:
    printf("ERROR");

}


printf(BLU"\nBye\n"RESET);
close (ds);
return 0;


}