#include "failure_detection.h"
#define DEBUG

extern uint32_t destinationAddress;
extern int is_failure;

#define PACKET_SIZE     2048
#define MAX_WAIT_TIME   5
#define MAX_NO_PACKETS  3
char sendpacket[PACKET_SIZE];
char recvpacket[PACKET_SIZE];
int datalen=56;
int nsend=0,nreceived=0;
pid_t pid;
struct sockaddr_in dest,from;
struct timeval tvrecv;
int size = 50*1024;
int socketDetect;

void *detect_failure(){
	//pthread_detach(pthread_self());
	
	//wait the sender to send packets
	while(destinationAddress == 0){
	}
	
	#ifdef DEBUG
	printf("The destination address in detection thread is %u\n", destinationAddress);
	#endif
	
	socketDetect = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if(socketDetect < 0){
		perror("socket() error");
		exit(1);
	}
	
	//expand the size of receiver buffer to avoid overflow
	if(setsockopt(socketDetect, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size))){
		perror("set receiver buffer size error");
		exit(1);
	}
	#ifdef DEBUG
	printf("The detection socket has been created and set\n");
	#endif
	bzero(&dest, sizeof(dest));
	dest.sin_family = AF_INET;
	dest.sin_addr.s_addr = destinationAddress;
	pid = getpid();
	
	//if the failure does not occur, then continue probing
	while(is_failure == 0){
		nsend = 0;
		nreceived = 0;
		send_packet();
		recv_packet();
		statistics(SIGALRM);
	}
	close(socketDetect);
	
	return NULL;
	
}


int pack(int pack_no){
	memset(sendpacket, 0, sizeof(sendpacket));
	int i,packsize;
	struct icmp* icmp;
	struct timeval* tval;
	icmp = (struct icmp*)sendpacket;
	icmp->icmp_type = ICMP_ECHO;
	icmp->icmp_code = 0;
	icmp->icmp_seq = pack_no;
	icmp->icmp_id = pid;
	packsize = 8 + datalen;
	tval = (struct timeval*)icmp->icmp_data; //save the sending time in the icmp data field
	gettimeofday(tval, NULL);
	//icmp->icmp_cksum = 0;
	icmp->icmp_cksum = cal_chksum((unsigned short*) icmp, packsize);
	return packsize;
}

void send_packet(){
	int packetsize;
	while(nsend < MAX_NO_PACKETS){
		nsend++;
		packetsize = pack(nsend);
		if(sendto(socketDetect, sendpacket, packetsize, 0, (struct sockaddr*)&dest, sizeof(dest))<0){
			perror("sendto error");
			continue;
		}
		//sleep(1);
	}
}

void recv_packet(){
	int n, fromlen;
	//signal(SIGALRM,statistics);
	fromlen = sizeof(from);
	time_t start = time(NULL);
	time_t waitTime = 1;
	time_t curTime = time(NULL);
	while(curTime - start < waitTime){
		//alarm(MAX_WAIT_TIME);
		//if(is_failure == 1)break;
		if((n=recvfrom(socketDetect,recvpacket,sizeof(recvpacket),MSG_DONTWAIT,(struct sockaddr*)&from, &fromlen))<=0){
			//printf("receive error is %d: ", n);
			//if(errno == EINTR)continue;
			//perror("recvfrom error");
			curTime = time(NULL);
			continue;
		}
		gettimeofday(&tvrecv, NULL);
		if(unpack(recvpacket,n)==-1)continue;
		nreceived++;
		curTime = time(NULL);
	}
}

int unpack(char *buf, int len){
	int i, iphdrlen;
	struct ip* ip;
	struct icmp* icmp;
	struct timeval *tvsend;
	double rtt;
	ip = (struct ip*)buf;
	iphdrlen = ip->ip_hl << 2;
	icmp = (struct icmp*)(buf + iphdrlen);
	len -= iphdrlen;
	if(len < 8){
		printf("ICMP packets length is less than 8\n");
		return -1;
	}
	if((icmp->icmp_type == ICMP_ECHOREPLY) && ((icmp->icmp_id)==pid)){
		tvsend = (struct timeval*)icmp->icmp_data;
		tv_sub(&tvrecv, tvsend);
		rtt = tvrecv.tv_sec*1000 + tvrecv.tv_usec/1000;
		 printf("%d byte from %s: icmp_seq=%u ttl=%d rtt=%.3f ms\n",
                        len,
                        inet_ntoa(from.sin_addr),
                        icmp->icmp_seq,
                        ip->ip_ttl,
                        rtt);
		return 0;
		
	}
	else return -1;
}

void statistics(int signo){
	 printf("\n--------------------PING statistics-------------------\n");
     printf("%d packets transmitted, %d received , %%%f lost\n",nsend,nreceived,
                        (nsend-nreceived)/(double)nsend*100);
	if(nreceived == 0){
		is_failure = 1;
		
		//pthread_exit(NULL);
	}
	else{
		is_failure = 0;
	}
}

unsigned short cal_chksum(unsigned short *addr,int len)
{       int nleft=len;
        int sum=0;
        unsigned short *w=addr;
        unsigned short answer=0;
		
        while(nleft>1)
        {       sum+=*w++;
                nleft-=2;
        }
        if( nleft==1)
        {       *(unsigned char *)(&answer)=*(unsigned char *)w;
                sum+=answer;
        }
        sum=(sum>>16)+(sum&0xffff);
        sum+=(sum>>16);
        answer=~sum;
        return answer;
}

void tv_sub(struct timeval *out,struct timeval *in)
{       if( (out->tv_usec-=in->tv_usec)<0)
        {       --out->tv_sec;
                out->tv_usec+=1000000;
        }
        out->tv_sec-=in->tv_sec;
}


