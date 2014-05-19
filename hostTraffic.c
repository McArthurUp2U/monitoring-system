/*
 * hostTraffic.c
 *
 * Copyright (C) 2014 by wangs
 * 
 *
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <search.h>
#include <pcap.h>
#include <signal.h>
#include <arpa/inet.h>
#include  <net/ethernet.h>
#include <netinet/ip.h>

//pcap
static char _pcap_error_buffer[PCAP_ERRBUF_SIZE];
static pcap_t *_pcap_handle = NULL;
static int _pcap_datalink_type = 0;
static u_int8_t shutdown_app = 0;
static char *_pcap_file = "eth0_rename";


//global data structure
struct hostTraffic
{
	u_int8_t exist;
	char ip[20];
	u_int64_t bytes;
};
u_int32_t mask; 
u_int64_t last_bytes[255];

struct hostTraffic ht_global[255];

static struct timeval begin, now, last;
int capture_until = 0;

static u_int64_t raw_packet_count = 0;


void sigproc(int sig);
static void openPcapFileOrDevice(void);
static void pcap_packet_callback(u_char * args, const struct pcap_pkthdr *header, const u_char * packet);
char* formatTraffic(float numBits, int bits, char *buf) ;
int main()
{
	int i;
	openPcapFileOrDevice();
	for (i = 0;i < 255; i++){

		ht_global[i].exist = 0;
		ht_global[i].bytes = 0;
	}
	mask = inet_network("255.255.255.0");
	gettimeofday(&begin, NULL);
	last = begin;
	if((!shutdown_app) && (_pcap_handle != NULL))
		pcap_loop(_pcap_handle, -1, &pcap_packet_callback, NULL);
	//其中第一个参数是winpcap的句柄,第二个是指定捉拿的数据包个数,为-1则无限循环捉拿。第四个参数user是留给用户利用的。
	
	return 0;
}
static void openPcapFileOrDevice(void)
{
  u_int snaplen = 1514;
  int promisc = 1;
  char errbuf[PCAP_ERRBUF_SIZE];
  
  if((_pcap_handle = pcap_open_live(_pcap_file, snaplen, promisc, 500, errbuf)) == NULL) {
    _pcap_handle = pcap_open_offline(_pcap_file, _pcap_error_buffer);
    capture_until = 0;

    if (_pcap_handle == NULL) {
      printf("ERROR: could not open pcap file: %s\n", _pcap_error_buffer);
      exit(-1);
    } else
      printf("Reading packets from pcap file %s...\n", _pcap_file);
  } else
    printf("Capturing live traffic from device %s...\n", _pcap_file);

  _pcap_datalink_type = pcap_datalink(_pcap_handle);

 signal(SIGINT, sigproc);
  if(capture_until > 0) {
    printf("Capturing traffic up to %u seconds\n", (unsigned int)capture_until);

    alarm(capture_until);
    capture_until += time(NULL);    
  }
}

void sigproc(int sig)
{
	printf("\n");
	int i = 0,j=0;
	char buf[32];
	char buf2[32];
	char buf3[32];
	gettimeofday(&now, NULL);
	printf("%3s %-13s %13s %13s/s %13s/s\n","seq", "ip address", "traffic B","average B", "current B");
	for (i = 0; i < 255; i++){
		if(ht_global[i].exist == 1)
		{
			j++;
			
			printf("%3d %-13s %13s %13s/s %13s/s\n", j, ht_global[i].ip, formatTraffic(ht_global[i].bytes, 0, buf),
			formatTraffic((float)ht_global[i].bytes/(now.tv_sec - begin.tv_sec), 0, buf2), 
			formatTraffic((float)(ht_global[i].bytes - last_bytes[i])/(now.tv_sec + (float)now.tv_usec/1000000 - last.tv_sec
			- (float)last.tv_usec/1000000), 0, buf3));
			last_bytes[i] = ht_global[i].bytes;
			
		}
		
	}
	last = now;
}
static void pcap_packet_callback(u_char * args, const struct pcap_pkthdr *header, const u_char * packet)
/*
 * 
 * 	struct pcap_pkthdr {
	struct timeval ts; // 工夫戳 
	bpf_u_int32 caplen; // 已捉拿局部的长度  
	bpf_u_int32 len; // 该包的脱机长度  
};
*/
{	
  struct  ether_header *ethernet;//以太网头部。
  
  struct iphdr *iph;//代表IP头部所有内容。
  raw_packet_count++;
  int i=0;
	int saddr, daddr;
  u_int32_t ip_offset;
	struct in_addr ia;
	
	if ((header->ts.tv_usec) > 0){
	
		if(_pcap_datalink_type == DLT_EN10MB) {
			ethernet = (struct  ether_header *)packet;
			ip_offset = sizeof(struct ether_header);
			iph = (struct iphdr *) &packet[ip_offset];
			
			//printf("%llu leongth %u ", raw_packet_count, header->caplen);
			//for ( i = 0; i < 6; i++){
			//	printf("%x", ethernet->ether_dhost[i]);
			//	if (i < 5)
			//		printf(":");
			//	else
			//		printf(" ");
			//}
			//printf("Source:%s ", inet_ntoa(*(( struct in_addr *)&iph->saddr))); 
			//printf("%u ", ntohl(iph->saddr));
			//printf("%u ", mask);
			//printf("Destination:%s ", inet_ntoa(*((struct in_addr *)&iph->daddr))); 
			if ((mask & ntohl(iph->saddr)) == inet_network("10.108.86.0"))
			{
				saddr = ntohl(iph->saddr)%256;
			//	printf("saddr %d", saddr);
				ht_global[saddr].exist = 1;
				ia.s_addr = iph->saddr;
				strcpy(ht_global[saddr].ip, inet_ntoa(ia));
				ht_global[saddr].bytes += header->caplen;
				//printf("in !!!");
			}
			else if ((mask & ntohl(iph->daddr)) == inet_network("10.108.86.0"))
			{
				daddr = ntohl(iph->daddr)%256;
			//	printf("daddr %d", daddr);
				ht_global[daddr].exist = 1;
				ia.s_addr = iph->daddr;
				strcpy(ht_global[daddr].ip, inet_ntoa(ia));
				ht_global[saddr].bytes += header->caplen;

			//	printf("in !!!");
			}
			//printf("\n");



		}
		
	}
}
char* formatTraffic(float numBits, int bits, char *buf) {
  char unit;

  if(bits)
    unit = 'b';
  else
    unit = 'B';

  if(numBits < 1024) {
    snprintf(buf, 32, "%lu %c", (unsigned long)numBits, unit);
  } else if (numBits < 1048576) {
    snprintf(buf, 32, "%.2f K%c", (float)(numBits)/1024, unit);
  } else {
    float tmpMBits = ((float)numBits)/1048576;

    if(tmpMBits < 1024) {
      snprintf(buf, 32, "%.2f M%c", tmpMBits, unit);
    } else {
      tmpMBits /= 1024;

      if(tmpMBits < 1024) {
	snprintf(buf, 32, "%.2f G%c", tmpMBits, unit);
      } else {
	snprintf(buf, 32, "%.2f T%c", (float)(tmpMBits)/1024, unit);
      }
    }
  }

  return(buf);
}
