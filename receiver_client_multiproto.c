/* ========================================================
 *   Copyright (C) 2015 All rights reserved.
 *
 *   filename : client.c
 *   author   : zhangxiao@dislab.nju.edu.cn
 *   date     : 2015-3-30
 *
 * ======================================================== */

#include <string.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <ifaddrs.h>

#include <asm/byteorder.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <errno.h>

//#define DEBUG

#ifdef __LITTLE_ENDIAN
#define IPQUAD(addr) \
    ((unsigned char *)&addr)[0],                  \
    ((unsigned char *)&addr)[1],                \
    ((unsigned char *)&addr)[2],                \
    ((unsigned char *)&addr)[3]
#else
#define IPQUAD(addr)                            \
  ((unsigned char *)&addr)[3],                  \
    ((unsigned char *)&addr)[2],                \
    ((unsigned char *)&addr)[1],                \
    ((unsigned char *)&addr)[0]
#endif

#define MAXLEN 2048
#define TCP 6
#define UDP 17
int sockfd = 0;
int is_failure = 0;
int is_send = 1;

char hname[128];
struct hostent *hent;
struct ifaddrs* ifAddr=NULL;
char* landmarkfile = "landmark.txt";
uint32_t landmark;

uint32_t destinationAddress = 0;

uint32_t get_landmark(){
	FILE *fp;
	fp = fopen(landmarkfile,"r");
	if(fp == NULL){
		fprintf(stderr, "cannot open landmark file");
		exit(1);
	}
	char landmarkip[30];
	fgets(landmarkip, sizeof(landmarkip), fp);
	fclose(fp);
	fprintf(stderr,"The landmark ip is %s", landmarkip);
	return inet_addr(landmarkip);

}

u_int16_t tcp_sum_calc(u_int16_t len_tcp, u_int16_t src_addr[], u_int16_t dest_addr[], u_int16_t buff[])
{
    u_int16_t prot_tcp = 6;
    u_int32_t sum = 0 ;
    int nleft = len_tcp;
    u_int16_t *w = buff;

    /* calculate the checksum for the tcp header and payload */
    while(nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    /* if nleft is 1 there ist still on byte left. We add a padding byte (0xFF) to build a 16bit word */
    if(nleft>0)
		sum += *w&ntohs(0xFF00);   /* Thanks to Dalton */

    /* add the pseudo header */
    sum += src_addr[0];
    sum += src_addr[1];
    sum += dest_addr[0];
    sum += dest_addr[1];
    sum += htons(len_tcp);
    sum += htons(prot_tcp);

    // keep only the last 16 bits of the 32 bit calculated sum and add the carries
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    // Take the one's complement of sum
    sum = ~sum;

    return ((u_int16_t) sum);
}

void process_send_packet_udp(unsigned char* pkt, int pkt_len, int id,struct nfq_q_handle* qh){
    if(pkt_len > MAXLEN) pkt_len = MAXLEN;
    struct iphdr *ip = (struct iphdr*) pkt;
    struct udphdr *udph = (struct udphdr*) (pkt + ip->ihl*4);
    u_int32_t sour_addr, dest_addr;
    sour_addr = ip->saddr;
    dest_addr = ip->daddr;



	//determine whether the packet is sent by raw socket or not
	unsigned char* addrinfo = pkt + ip->ihl*4;
	if(pkt_len > ip->ihl*4 + 2*sizeof(u_int32_t)){
		uint32_t test_sour_addr = *((uint32_t*)addrinfo);
		uint32_t test_dst_addr = *((uint32_t*)(addrinfo + sizeof(u_int32_t)));
		if(test_sour_addr == sour_addr){
			nfq_set_verdict(qh, id, NF_ACCEPT, (u_int32_t)pkt_len, pkt);
			return;
		}
	}
	 printf("raw packet udp src port is %d, dest port is %d\n", ntohs(udph->source),ntohs(udph->dest));

	#ifdef DEBUG
	fprintf(stderr,"len %d iphdr %d %u.%u.%u.%u ->",
    	pkt_len,
        ip->ihl<<2,
        IPQUAD(ip->saddr));
  	fprintf(stderr," %u.%u.%u.%u",
        IPQUAD(ip->daddr));
  	fprintf(stderr,"\n");
	#endif

    unsigned char buf[MAXLEN + 10];

    unsigned char* nip_payload;


    struct sockaddr_in to;

    // copy ip header to new packet
    memcpy((void*)buf, (void*)pkt, (size_t )(ip->ihl*4));
    nip_payload = buf + ip->ihl*4;
    int i = 0;
    for(; i < sizeof(u_int32_t); i++){
        *nip_payload = *((unsigned char*)&sour_addr+i);
        nip_payload++;
    }
    for(i = 0; i < sizeof(u_int32_t); i++){
        *nip_payload = *((unsigned char*)&dest_addr+i);
        nip_payload++;
    }
    //copy udp packet to new packet
    u_int32_t udp_packet_len = pkt_len - ip->ihl*4;
    unsigned char* udp_packet = pkt + ip->ihl*4;
    struct iphdr* nip = (struct iphdr*) buf;
    memcpy((void*)nip_payload, (void*)udp_packet, (size_t )udp_packet_len);

    //send packet
    u_int32_t npkt_len = pkt_len + sizeof(sour_addr) + sizeof(dest_addr);
    nip->check = 0;
    nip->tot_len = htons(npkt_len);
    nip->daddr = landmark;
    to.sin_addr.s_addr = landmark;
    to.sin_family = AF_INET;

    #ifdef DEBUG
    struct udphdr* nudph = (struct udphdr*)(buf+ip->ihl*4+2*sizeof(uint32_t));
    printf("received udp src port is %d, dest port is %d\n", ntohs(nudph->source),ntohs(nudph->dest));
    struct in_addr dst;
    dst.s_addr = nip->daddr;
    printf("destination ip is %s\tlen is %d\n",inet_ntoa(dst), npkt_len);
    printf("IP id is %d\n", ip->id);
    #endif

    int r = sendto(sockfd, buf,npkt_len,0, (struct sockaddr *)&to, sizeof(to));
    nfq_set_verdict(qh, id, NF_DROP, (u_int32_t)pkt_len, pkt);
    if(r < 0){
        perror("sendto error");
    }
    fprintf(stderr, "send packet processed\n");

}

void process_receive_packet_udp(unsigned char* pkt, int pkt_len, int id,struct nfq_q_handle* qh){
    struct iphdr *ip = (struct iphdr*) pkt;

    uint32_t dst_addr = ip->daddr;
    //determine whether the packet is received from landmark
	unsigned char* addrinfo = pkt + ip->ihl*4;
	if(pkt_len > ip->ihl*4 + 2*sizeof(u_int32_t)){
		uint32_t test_sour_addr = *((uint32_t*)addrinfo);
		uint32_t test_dst_addr = *((uint32_t*)(addrinfo + sizeof(u_int32_t)));
		if(test_dst_addr == 0 || test_dst_addr != dst_addr){
			nfq_set_verdict(qh, id, NF_ACCEPT, (u_int32_t)pkt_len, pkt);
			return;
		}
	}
	else{
		nfq_set_verdict(qh, id, NF_ACCEPT, (u_int32_t)pkt_len, pkt);
		return;
	}

    #ifdef DEBUG
    fprintf(stderr, "receive a packet\n");
	fprintf(stderr,"len %d iphdr %d %u.%u.%u.%u ->",
    	pkt_len,
        ip->ihl<<2,
        IPQUAD(ip->saddr));
  	fprintf(stderr," %u.%u.%u.%u",
        IPQUAD(ip->daddr));
  	fprintf(stderr,"\n");
	#endif

	uint32_t conn_src_addr = *(uint32_t*)(pkt+ip->ihl*4);
    unsigned char* udp_packet = pkt + ip->ihl*4 + 2*sizeof(u_int32_t);
    struct udphdr* udph = (struct udphdr*)udp_packet;
    unsigned char* nudp_packet = pkt + ip->ihl*4;
    u_int32_t udp_len = pkt_len - ip->ihl*4 - 2*sizeof(u_int32_t);
    memcpy((void*)nudp_packet, (void*)udp_packet,(size_t )udp_len);
    struct udphdr* nudph = (struct udphdr*)nudp_packet;

    ip->saddr = conn_src_addr;


    u_int32_t pdata_len = pkt_len - 2*sizeof(u_int32_t);
    ip->tot_len = htons(pdata_len);
	#ifdef DEBUG
	printf("reveived ip check is %d\n",ip->check);
	  printf("received udp src port is %d, dest port is %d\n", ntohs(nudph->source),ntohs(nudph->dest));
	  fprintf(stderr,"conninfo: %u.%u.%u.%u ->",
        IPQUAD(ip->saddr));
  	fprintf(stderr," %u.%u.%u.%u",
        IPQUAD(ip->daddr));
  	fprintf(stderr,"\n");
  	 fprintf(stderr, "received packet processed\n");
	#endif
	//ip->check = 0;
    nfq_set_verdict(qh, id, NF_ACCEPT, (u_int32_t)pdata_len, pkt);



}

void process_send_packet_tcp(unsigned char* pkt, int pkt_len, int id,struct nfq_q_handle* qh){
    if(pkt_len > MAXLEN) pkt_len = MAXLEN;
    struct iphdr *ip = (struct iphdr*) pkt;
    struct tcphdr *tcph = (struct tcphdr*) (pkt + ip->ihl*4);
    u_int32_t sour_addr, dest_addr;
    sour_addr = ip->saddr;
    dest_addr = ip->daddr;



	//determine whether the packet is sent by raw socket or not
	unsigned char* addrinfo = pkt + ip->ihl*4;
	if(pkt_len > ip->ihl*4 + 2*sizeof(u_int32_t)){
		uint32_t test_sour_addr = *((uint32_t*)addrinfo);
		uint32_t test_dst_addr = *((uint32_t*)(addrinfo + sizeof(u_int32_t)));
		if(test_sour_addr == sour_addr){
			nfq_set_verdict(qh, id, NF_ACCEPT, (u_int32_t)pkt_len, pkt);
			return;
		}
	}
	 printf("raw packet tcp src port is %d, dest port is %d\n", ntohs(tcph->source),ntohs(tcph->dest));

	#ifdef DEBUG
	fprintf(stderr,"len %d iphdr %d %u.%u.%u.%u ->",
    	pkt_len,
        ip->ihl<<2,
        IPQUAD(ip->saddr));
  	fprintf(stderr," %u.%u.%u.%u",
        IPQUAD(ip->daddr));
  	fprintf(stderr,"\n");
	#endif

    unsigned char buf[MAXLEN + 10];

    unsigned char* nip_payload;


    struct sockaddr_in to;

    // copy ip header to new packet
    memcpy((void*)buf, (void*)pkt, (size_t )(ip->ihl*4));
    nip_payload = buf + ip->ihl*4;
    int i = 0;
    for(; i < sizeof(u_int32_t); i++){
        *nip_payload = *((unsigned char*)&sour_addr+i);
        nip_payload++;
    }
    for(i = 0; i < sizeof(u_int32_t); i++){
        *nip_payload = *((unsigned char*)&dest_addr+i);
        nip_payload++;
    }
    //copy tcp packet to new packet
    u_int32_t tcp_packet_len = pkt_len - ip->ihl*4;
    unsigned char* tcp_packet = pkt + ip->ihl*4;
    struct iphdr* nip = (struct iphdr*) buf;
    memcpy((void*)nip_payload, (void*)tcp_packet, (size_t )tcp_packet_len);

    //send packet
    u_int32_t npkt_len = pkt_len + sizeof(sour_addr) + sizeof(dest_addr);
    nip->check = 0;
    nip->tot_len = htons(npkt_len);
    nip->daddr = landmark;
    to.sin_addr.s_addr = landmark;
    to.sin_family = AF_INET;

    #ifdef DEBUG
    struct tcphdr* ntcph = (struct tcphdr*)(buf+ip->ihl*4+2*sizeof(uint32_t));
    printf("received tcp src port is %d, dest port is %d\n", ntohs(ntcph->source),ntohs(ntcph->dest));
    struct in_addr dst;
    dst.s_addr = nip->daddr;
    printf("destination ip is %s\tlen is %d\n",inet_ntoa(dst), npkt_len);
    printf("IP id is %d\n", ip->id);
    #endif

    int r = sendto(sockfd, buf,npkt_len,0, (struct sockaddr *)&to, sizeof(to));
    nfq_set_verdict(qh, id, NF_DROP, (u_int32_t)pkt_len, pkt);
    if(r < 0){
        perror("sendto error");
    }
    fprintf(stderr, "send packet processed\n");

}

void process_receive_packet_tcp(unsigned char* pkt, int pkt_len, int id,struct nfq_q_handle* qh){
    struct iphdr *ip = (struct iphdr*) pkt;

    uint32_t dst_addr = ip->daddr;
    //determine whether the packet is received from landmark
	unsigned char* addrinfo = pkt + ip->ihl*4;
	if(pkt_len > ip->ihl*4 + 2*sizeof(u_int32_t)){
		uint32_t test_sour_addr = *((uint32_t*)addrinfo);
		uint32_t test_dst_addr = *((uint32_t*)(addrinfo + sizeof(u_int32_t)));
		if(test_dst_addr == 0 || test_dst_addr != dst_addr){
			nfq_set_verdict(qh, id, NF_ACCEPT, (u_int32_t)pkt_len, pkt);
			return;
		}
	}
	else{
		nfq_set_verdict(qh, id, NF_ACCEPT, (u_int32_t)pkt_len, pkt);
		return;
	}

    #ifdef DEBUG
    fprintf(stderr, "receive a packet\n");
	fprintf(stderr,"len %d iphdr %d %u.%u.%u.%u ->",
    	pkt_len,
        ip->ihl<<2,
        IPQUAD(ip->saddr));
  	fprintf(stderr," %u.%u.%u.%u",
        IPQUAD(ip->daddr));
  	fprintf(stderr,"\n");
	#endif

	uint32_t conn_src_addr = *(uint32_t*)(pkt+ip->ihl*4);
    unsigned char* tcp_packet = pkt + ip->ihl*4 + 2*sizeof(u_int32_t);
    struct tcphdr* tcph = (struct tcphdr*)tcp_packet;
    unsigned char* ntcp_packet = pkt + ip->ihl*4;
    u_int32_t tcp_len = pkt_len - ip->ihl*4 - 2*sizeof(u_int32_t);
    memcpy((void*)ntcp_packet, (void*)tcp_packet,(size_t )tcp_len);
    struct tcphdr* ntcph = (struct tcphdr*)ntcp_packet;

    ip->saddr = conn_src_addr;


    u_int32_t pdata_len = pkt_len - 2*sizeof(u_int32_t);
    ip->tot_len = htons(pdata_len);
	#ifdef DEBUG
	printf("reveived ip check is %d\n",ip->check);
	  printf("received tcp src port is %d, dest port is %d\n", ntohs(ntcph->source),ntohs(ntcph->dest));
	  fprintf(stderr,"conninfo: %u.%u.%u.%u ->",
        IPQUAD(ip->saddr));
  	fprintf(stderr," %u.%u.%u.%u",
        IPQUAD(ip->daddr));
  	fprintf(stderr,"\n");
  	 fprintf(stderr, "received packet processed\n");
	#endif
	//ip->check = 0;
    nfq_set_verdict(qh, id, NF_ACCEPT, (u_int32_t)pdata_len, pkt);



}

static int cb(struct nfq_q_handle* qh, struct nfgenmsg* nfmsg, struct nfq_data* nfa, void *data){
    u_int32_t id = 0;
    struct nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(nfa);
    unsigned char* pdata = NULL;
    int pdata_len;
    int i;
    if(ph)
        id = ntohl(ph->packet_id);


    pdata_len = nfq_get_payload(nfa, (unsigned char**)&pdata);
    if(pdata_len == -1){
        pdata_len = 0;
    }
    struct iphdr* iphdrp = (struct iphdr*)pdata;

    if(!is_failure){

		if(iphdrp->saddr == landmark){
			is_failure = 1;
		}
		else{
			return nfq_set_verdict(qh, id, NF_ACCEPT, 0 ,NULL);
		}
    }







    #ifdef DEBUG
    /*uint32_t srcaddr = inet_addr("114.212.84.201");
    uint32_t dstaddr1 = inet_addr("114.212.82.165");
    uint32_t dstaddr2 = inet_addr("114.212.82.140");

	if((iphdrp->daddr == dstaddr1 || iphdrp->saddr == dstaddr2)){
	}
	else{
		nfq_set_verdict(qh, id, NF_ACCEPT, (u_int32_t)pdata_len, pdata);
		return 0;
	}*/
	 #endif

	uint32_t loaddr = inet_addr("127.0.0.1");
	if(iphdrp->saddr == loaddr || iphdrp->daddr == loaddr){
		return 0;
	}




    //***********determine whether the packet is sent or received**********
    struct ifaddrs* iaddr = ifAddr;
    while(iaddr!=NULL){

		if(iaddr->ifa_addr->sa_family != AF_INET){
			iaddr = iaddr->ifa_next;
			continue;
		}


		u_int32_t addr = (u_int32_t)(((struct sockaddr_in*)iaddr->ifa_addr)->sin_addr.s_addr);

		if(addr == (u_int32_t)iphdrp->saddr){
			is_send = 1;
			#ifdef DEBUG
			//printf("The packet is to be sent");
			#endif
			break;
		}
		else if(addr == (u_int32_t)iphdrp->daddr){
			is_send = 0;
			#ifdef DEBUG
			//printf("The packet is to be received");
			#endif
			break;
		}
		iaddr = iaddr->ifa_next;

	}
    //*********************************************************************
    if(is_send){
        if(iphdrp->protocol == TCP)
            process_send_packet_tcp(pdata,pdata_len,id,qh);
        else if(iphdrp->protocol==UDP)
            process_send_packet_udp(pdata,pdata_len,id,qh);
        else
            nfq_set_verdict(qh, id, NF_ACCEPT, (u_int32_t)pdata_len, pdata);

    }
    else{
        if(iphdrp->protocol == TCP)
            process_receive_packet_tcp(pdata, pdata_len, id, qh);
        else if(iphdrp->protocol == UDP)
            process_receive_packet_udp(pdata, pdata_len, id, qh);
        else
            nfq_set_verdict(qh, id, NF_ACCEPT, (u_int32_t)pdata_len, pdata);
    }


    return 0;


}

int main(int argc, char** argv){
    struct nfq_handle* h;
    struct nfq_q_handle* qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));
    int i;
    gethostname(hname, sizeof(hname));

    hent = gethostbyname(hname);

	getifaddrs(&ifAddr);
    #ifdef DEBUG
    /*printf("hostname: %s\n address list: ", hent->h_name);
    for(i = 0; hent->h_addr_list[i]; i++){
        printf("%s\t", inet_ntoa(*(struct in_addr*)(hent->h_addr_list[i])));
    }
    printf("\n");*/
    struct ifaddrs* iaddr = ifAddr;
    while(iaddr!=NULL){
		if(iaddr->ifa_addr->sa_family == AF_INET){
			//is a valid Ipv4 address
			printf("%s\t", inet_ntoa(((struct sockaddr_in*)iaddr->ifa_addr)->sin_addr));
		}
		iaddr = iaddr->ifa_next;
	}
	printf("\n");
    #endif

    landmark = get_landmark();


    h = nfq_open();
    if(!h){
        exit(1);
    }
    if(nfq_unbind_pf(h,AF_INET) < 0){
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }
    if(nfq_bind_pf(h,AF_INET) < 0){
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("open raw socket\n");
    if((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0){
        perror("create error\n");
        exit(1);
    }
    const int on = 1;
    if(setsockopt(sockfd,IPPROTO_IP,IP_HDRINCL, &on,sizeof(on))){
        perror("set IP_HDRINCL failed\n");
        exit(1);
    }

    int size = 100000*1024;
    if(setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size))){
		perror("set send buffer size error");
		exit(1);
	}

    qh = nfq_create_queue(h, 0, &cb, NULL);
    if(!qh){
		fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }
    if(nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0){
		fprintf(stderr, "cant set packet_copy mode\n");
        exit(1);
    }


    fd = nfq_fd(h);

    if(setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size))){
		perror("set receiver buffer size error");
		exit(1);
	}

    while(1){
        rv = recv(fd, buf, sizeof(buf), 0);
        if(rv >= 0){
			//printf("packet received\n");
			nfq_handle_packet(h, buf,rv);
		}

        else{
            fprintf(stderr, "recv got %d, errno = %d\n",rv, errno);
            //break;
        }
    }
    nfq_destroy_queue(qh);
    nfq_close(h);
    exit(0);
}
