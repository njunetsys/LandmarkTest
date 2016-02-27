#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include "failure_detection.h"

uint32_t destinationAddress = 0;
int is_failure = 0;

int main(){
	printf("hello\n");
	pthread_t tid;
	pthread_create(&tid, NULL, detect_failure, NULL);
	destinationAddress = inet_addr("114.212.82.165");
	printf("The destination address in main thread is: %u \n", destinationAddress);
	while(1){
		if(is_failure){
			//pthread_join(tid, NULL);
			printf("failure occurs\n");
			break;
		}
		else{
			printf("No failure occurs\n");
		}
		sleep(1);
	}
	return 0;
}
