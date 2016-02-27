#ifndef _failure_detection_h
#define _failure_detection_h
#include <stdio.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <errno.h>

void *detect_failure();
void send_packet();
void recv_packet();
int pack(int pack_no);
void statistics(int signo);
unsigned short cal_chksum(unsigned short *addr,int len);
int unpack(char *buf,int len);
void tv_sub(struct timeval *out,struct timeval *in);

#endif
