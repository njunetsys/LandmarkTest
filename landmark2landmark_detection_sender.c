#include <stdio.h>      /* for printf() and fprintf() */
#include <sys/socket.h> /* for socket(), connect(), sendto(), and recvfrom() */
#include <arpa/inet.h>  /* for sockaddr_in and inet_addr() */
#include <stdlib.h>     /* for atoi() and exit() */
#include <string.h>     /* for memset() */
#include <unistd.h>     /* for close() */
#include <time.h>

#define ECHOMAX 255     /* Longest string to echo */
#define LANDMARKMAX 100


void DieWithError(char *errorMessage)
{
    perror(errorMessage);
    exit(1);
}

uint32_t landmark[LANDMARKMAX];
uint32_t landmark_num = 0;

void get_landmark()
{
    FILE *fp;
    char* landmarkFile = "detection_landmark.txt";
    fp = fopen(landmarkFile,"r");
    if(fp==NULL)
    {
        fprintf(stderr, "can not open the landmark file");
        exit(1);
    }
    char tmp[50];

    while(fgets(tmp,100,fp))
    {
        landmark[landmark_num++] = inet_addr(tmp);
    }
    //printf("Handling client %s\n", inet_ntoa(echoClntAddr.sin_addr));
    fclose(fp);
}

int main(int argc, char *argv[])
{
    get_landmark();
    int sock;                        /* Socket descriptor */
    struct sockaddr_in echoServAddr; /* Echo server address */
    struct sockaddr_in fromAddr;     /* Source address of echo */
    unsigned short echoServPort;     /* Echo server port */
    unsigned int fromSize;           /* In-out of address size for recvfrom() */
    char *servIP;                    /* IP address of server */
    char *echoString;                /* String to send to echo server */
    char echoBuffer[ECHOMAX+1];      /* Buffer for receiving echoed string */
    int echoStringLen;               /* Length of string to echo */
    int respStringLen;               /* Length of received response */
    float myThroughput = 1.0;

    if (argc!=2)
    {
    fprintf(stderr,"Usage: %s <Echo Port>\n", argv[0]);
        exit(1);
    }
    echoServPort = atoi(argv[1]);  /* Use given port, if any */
     /* Create socket for sending/receiving datagrams */
    if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
        DieWithError("socket() failed");
    int i = 0;
    while(1)
    {
        for(i = 0; i < landmark_num; i++)
        {
            memset(&echoServAddr, 0, sizeof(echoServAddr));    /* Zero out structure */
            echoServAddr.sin_family = AF_INET;                 /* Internet addr family */
            echoServAddr.sin_addr.s_addr = landmark[i];  /* Server IP address */
            echoServAddr.sin_port   = htons(echoServPort);     /* Server port */
            if (sendto(sock, (void*)&myThroughput, sizeof(myThroughput), 0, (struct sockaddr *)
                       &echoServAddr, sizeof(echoServAddr)) != sizeof(myThroughput))
                DieWithError("sendto() sent a different number of bytes than expected");
        }
        uint32_t startTime = time(NULL);
        uint32_t curTime = time(NULL);
        while(curTime <= startTime){
            int fromSize = sizeof(fromAddr);
            int respLen = recvfrom(sock, echoBuffer, ECHOMAX, MSG_DONTWAIT, (struct sockaddr*)&fromAddr, &fromSize);
            if(respLen>0){
                printf("The received throughput is %lf\n",(float*)echoBuffer);
            }
            curTime = time(NULL);
        }

    }

    close(sock);
    exit(0);
    return 0;
}
