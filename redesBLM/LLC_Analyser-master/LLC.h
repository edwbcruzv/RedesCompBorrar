#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/time.h>
#include <stdbool.h>
#include <math.h>

void printFrame(unsigned char *frame, int tam);
void Read_File(char* file_name);
void Read_Network();
void LLC_Analyser(unsigned char *frame);
void DSAP_Analyser(int dsap);
void SSAP_Analyser(int ssap);
void SAP_Switch(int n);
void Control(int byte_1, int byte_2);
void Int_to_Binary_String(char *buffer, int num);
int Binary_String_to_Int(char *cadena);