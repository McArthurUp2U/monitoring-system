/*
 * ipq_usr.c
 *
 * Using ip_queue
 * recv packets from iptable's mangle table queue. packeging it to pcap format file to be anylysed by pcapReader.
 *
 */
#include <stdio.h>  
#include <stdlib.h>  
#include <string.h>  
#include <signal.h>  
#include <netinet/ip_icmp.h>  
#include <netinet/ip.h>  
#include <arpa/inet.h>  
#include <libipq.h>  

 
struct ipq_handle *h = NULL;
int sockfd;
 
static void sig_int(int signo)
{
      ipq_destroy_handle(h);
      printf("Exit: %s\n", ipq_errstr());
      exit(0);
}
 
int main(int argc, char** argv)
{
	char a = 'a';
	int b;
	int port = 60000;
	if((sockfd=socket(AF_INET,SOCK_DGRAM,0))==-1)
	{
		perror("socket creat failed!");
		exit(1);
	}
	int len, i;
	
	struct sockaddr_in server_addr, from;
	int addr_len = sizeof(from);
	if((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) 
	{
		perror("create socket");
	}
    server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	server_addr.sin_port = htons(port);
	
	  unsigned char buf[2048];
      /* creat handle*/
      h = ipq_create_handle(0, PF_INET);
      if(h == NULL){
           printf("%s\n", ipq_errstr());
           return 0;
      }
      printf("ipq_creat_handle success!\n");
      /*set mode*/
      unsigned char mode = IPQ_COPY_PACKET;
      int range = sizeof(buf);
      int ret = ipq_set_mode(h, mode, range);
      printf("ipq_set_mode: send bytes =%d, range=%d\n", ret, range);
     
      /*register signal handler*/
      signal(SIGINT, sig_int);
 
      /*read packet from kernel*/
      int status;
      struct nlmsghdr *nlh;
      ipq_packet_msg_t *ipq_packet;
	  FILE *f;
     
	 
	 
	
      while(1){
           status = ipq_read(h, buf, sizeof(buf), 0);
		   f = fopen("packet_cache", "w");
           if(status > sizeof(struct nlmsghdr))
           {
                 nlh = (struct nlmsghdr *)buf;
                 ipq_packet = ipq_get_packet(buf);
                 printf("recv bytes =%d, nlmsg_len=%d, indev=%s, datalen=%d, packet_id=%x\n", status, nlh->nlmsg_len,
                            ipq_packet->indev_name,  ipq_packet->data_len, ipq_packet->packet_id);
				 unsigned char payload[4096];  
                 memset(payload, 0x00, sizeof(payload));  
                 memcpy(payload + 54, ipq_packet->payload, ipq_packet->data_len); 
				 payload[3] = 0xa1;
				 payload[2] = 0xb2;
				 payload[1] = 0xc3; 
				 payload[0] = 0xd4; 
				 payload[4] = 0x02;   
				 payload[6] = 0x04;   
				 payload[16] = 0xff;
				 payload[17] = 0xff;
				 payload[20] = 0x01;
				 payload[32] = (ipq_packet->data_len + 14)%256;
				 payload[33] = (ipq_packet->data_len + 14)/256;
				 payload[36] = (ipq_packet->data_len + 14)%256;
				 payload[37] = (ipq_packet->data_len + 14)/256;
				 payload[52] = 0x08 ;
				 fwrite(payload,1,ipq_packet->data_len + 54 ,f);
				 fclose(f);
				 addr_len = sizeof(server_addr);
				 sendto(sockfd,&a,sizeof(a),0,(struct sockaddr *)&server_addr,sizeof(server_addr));
				 len = recvfrom(sockfd, &b, sizeof(b), 0,
				(struct sockaddr *)&server_addr, &addr_len);
				
				printf("0x%x\n" ,b);
				printf("0x%x\n" ,atoi(argv[1]));
				for (i = 1; i < argc; i++)
				{
					if ( b == atoi(argv[i]))
					{
						ipq_set_verdict(h, ipq_packet->packet_id, 0,ipq_packet->data_len,ipq_packet->payload); 
						printf(" drop\n");
					}
				}
						
				 ipq_set_verdict(h, ipq_packet->packet_id, 1,ipq_packet->data_len,ipq_packet->payload); 
           }
      }
      return 0;
}
