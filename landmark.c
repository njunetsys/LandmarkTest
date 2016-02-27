/* ========================================================
 *   Copyright (C) 2015 All rights reserved.
 *
 *   filename : landmark.c
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
#include <errno.h>

#define DEBUG

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
int sockfd = 0;

uint32_t find_next_hop(char* pdata){
	struct iphdr* ip = (struct iphdr*)pdata;
	char* dest = pdata + ip->ihl*4 + sizeof(uint32_t);
	return *((uint32_t*)dest);

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
	unsigned char* addrinfo = pdata + iphdrp->ihl*4;
	uint32_t conn_sour_addr, conn_dest_addr;
	//The packet is a reroute packet
	if(pdata_len > iphdrp->ihl*4 + 2*sizeof(uint32_t)){
		conn_sour_addr = *(uint32_t*)addrinfo;
		conn_dest_addr = *((uint32_t*)(addrinfo + sizeof(uint32_t)));
		// only work in the one-hop reroute
		if(iphdrp->saddr == 0 || iphdrp->daddr == 0 || conn_sour_addr!=iphdrp->saddr){
			nfq_set_verdict(qh, id, NF_ACCEPT, (u_int32_t)pdata_len, pdata);
			return 0;
		}
	}
	else{
		nfq_set_verdict(qh, id, NF_ACCEPT, (u_int32_t)pdata_len, pdata);
		return 0;
	}

	#ifdef DEBUG
	fprintf(stderr,"connection info: len %d iphdr %d %u.%u.%u.%u ->",
    	pdata_len,
        iphdrp->ihl<<2,
        IPQUAD(conn_sour_addr));
  	fprintf(stderr," %u.%u.%u.%u",
        IPQUAD(conn_dest_addr));
  	fprintf(stderr,"\n");
	#endif


	//modify the address of packet and reroute
	iphdrp->saddr = iphdrp->daddr;
	iphdrp->daddr = find_next_hop(pdata);
	iphdrp->check = 0;

	//*************************************************
	//modify the dest ip address and send the packet
	/*unsigned char buf[MAXLEN + 10];
	memcpy((void*)buf, (void*)pdata, (size_t )(iphdrp->ihl*4));
	char * tcp_payload = pdata + iphdrp->ihl*4 + 2*sizeof(uint32_t);
	char * nip_payload = buf + iphdrp->ihl*4;
	uint32_t tcp_packet_len = pdata_len - iphdrp->ihl*4 - 2*sizeof(uint32_t);
	memcpy((void*)nip_payload, (void*)tcp_payload, (size_t )tcp_packet_len);
	struct iphdr* nip = (struct iphdr*)buf;
	nip->daddr = find_next_hop(pdata);
	nip->check = 0;
	uint32_t npkt_len = pdata_len - 2*sizeof(uint32_t);
	nip->tot_len = htons(npkt_len);
	struct tcphdr* ntcph = (struct tcphdr*)(buf+nip->ihl*4);*/

	#ifdef DEBUG
	fprintf(stderr, "The reroute source is %u.%u.%u.%u, The reroute dest is %u.%u.%u.%u\n",IPQUAD(iphdrp->saddr),IPQUAD(iphdrp->daddr));
	//fprintf(stderr, "The ip protocol is %u\n", nip->protocol);
	//fprintf(stderr,"The source port is %d, The dest port is %d\n",ntohs(ntcph->source), ntohs(ntcph->dest));
	//fprintf(stderr,"Current sour addr is  %u.%u.%u.%u\n",IPQUAD(nip->saddr));
	printf("IP id is %d, len is %d\n", iphdrp->id,ntohs(iphdrp->tot_len));
	#endif

	struct sockaddr_in to;
	to.sin_addr.s_addr = iphdrp->daddr;
	to.sin_family = AF_INET;
	//to.sin_port = ntcph->dest;

	int r = sendto(sockfd, pdata, pdata_len, 0, (struct sockaddr*)&to, sizeof(to));
	nfq_set_verdict(qh, id, NF_DROP, (u_int32_t)pdata_len, pdata);
	if(r < 0){
		perror("sendto error");
		return 0;
	}
	#ifdef DEBUG
	fprintf(stderr,"reroute a packet\n");
	#endif

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

    int size = 100000*1024;
    if(setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size))){
		perror("set send buffer size error");
		exit(1);
	}

    const int on = 1;
    if(setsockopt(sockfd,IPPROTO_IP,IP_HDRINCL, &on,sizeof(on))){
        perror("set IP_HDRINCL failed\n");
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

