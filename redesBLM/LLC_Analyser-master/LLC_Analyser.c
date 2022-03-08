#include "LLC.c"
#include "comnet.c"

int main(int argc, char const *argv[])
{
    char option;
    int flag = 1;

    printf("Analizador de tramas LLC\n");
    printf(" 1.- Analizar tramas del archivo\n 2.- Analizar trama de la red\n 3.- Salir\n");
    while(flag)
    {
        scanf("%c", &option);
        if(option != ' ' || option != '\n')
            flag = 0;
    }

    switch (option)
    {
        case '1':    
            Read_File("tramas.txt");
        break;

        case '2':
            Read_Network();
        break;

        case '3':
            flag = 0;
        break;
        
        default:
            printf("Introduce una opcion valida");
        break;
    }

    return 0;
}