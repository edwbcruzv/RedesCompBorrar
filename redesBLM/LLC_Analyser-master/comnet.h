#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>

#include <linux/if_packet.h>
#include <net/ethernet.h>       /* the L2 protocols  */

#include <arpa/inet.h>          /* for htons function */ 
#include <unistd.h>             /* for close function */   

#include <sys/ioctl.h>          
#include <net/if.h>

#include <sys/time.h>

unsigned char my_MAC[6];
unsigned char my_IP[4];
unsigned char NETMASK[4];
unsigned int Metric;
unsigned int MTU;

unsigned char frame_r[1514];

struct timeval start, end;
long mtime, seconds, useconds;

int getData(int sd);
//void printFrame(unsigned char *frame, int size);
void receiveFrame(int sd, unsigned char *frame);