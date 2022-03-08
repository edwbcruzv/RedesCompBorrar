#include "comnet.c"

int main(int argc, char const *argv[])
{
    int packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	BD_MySQL_Connect();
	BD_MySQL_Reset_Data();

    if(packet_socket == -1) {
        perror("Error al abrir el socket.");
        exit(1);
    } else {
        perror("Exito al abrir el socket.");
        int index = getData(packet_socket);
        printf("El indice es %d\n", index);

		for(int i = 1; i < 255; i++)
		{
			getDestinationIP(i);
			ARPframe(frame_s, my_MAC, my_IP, dest_MAC, dest_IP);
			//printFrame(frame_s, 42);
			sendFrame(packet_socket, index, frame_s, 42);
			receiveFrame(packet_socket, frame_r);
		}
    }

	BD_MySQL_Show_Data();
	BD_MySQL_Close();

    close(packet_socket);

    return 0;
}