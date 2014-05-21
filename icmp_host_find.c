/*
 * Using ICMP to discovery hosts in LAN
 * some bugs :
 * 	netmask can't be larger than 255.255.255.0,so fix it to 255.255.255.0
 * 	Must run this program several times so that the result is stable.
 * 
 * 	Email:wangsquirrel@gmail.com
 */
#include <stdio.h> 
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h> 
#include <signal.h> 
#include <arpa/inet.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <unistd.h> 
#include <netinet/in.h> 
#include <netinet/ip.h> 
#include <netinet/ip_icmp.h> 
#include <netdb.h> 
#include <setjmp.h> 
#include <errno.h> 
#include <pthread.h>
#include <fcntl.h>
#include <net/if.h>


#define PACKET_SIZE 4096
#define MAX_SEND_TIMES 1
#define ICMP_DATA_LEN 56

char host[1030][20];
int host_num = 0;
unsigned long end_addr=0l;
unsigned long start_addr=0l;


struct timeval tv;// recv timeout
int size = 50 * 1024;// recv buffer
struct protoent *protocol;
pthread_mutex_t lock; 

void find_end_start_addr(char *);


void * find_host(void *);
void tv_sub(struct timeval *out,struct timeval *in);

/*校验和算法*/
unsigned short cal_chksum(unsigned short *addr,int len)
{     
	int nleft=len;
    int sum=0;
    unsigned short *w=addr;
    unsigned short answer=0;
  
/*把ICMP报头二进制数据以2字节为单位累加起来*/
    while(nleft>1)
    {       
		sum+=*w++;
    	nleft-=2;
    }
  /*若ICMP报头为奇数个字节，会剩下最后一字节。把最后一个字节视为一个2字节数据的高字节，这个2字节数据的低字节为0，继续累加*/
    if( nleft==1)
    {      
		 *(unsigned char *)(&answer)=*(unsigned char *)w;
         sum+=answer;
				
    }
    sum=(sum>>16)+(sum&0xffff);
    sum+=(sum>>16);
    answer=~sum;
    return answer;
}
/*设置ICMP报头*/
int pack(int pack_seq, char * sendpacket)
{
    int packsize;
    struct icmp *icmp;
    struct timeval *tval;
    icmp=(struct icmp*)sendpacket;
    icmp->icmp_type=ICMP_ECHO;
    icmp->icmp_code=0;
    icmp->icmp_cksum=0;
    icmp->icmp_seq=pack_seq;
    icmp->icmp_id=(unsigned short)pthread_self();
    packsize= 8 + ICMP_DATA_LEN;//8 head length
    tval= (struct timeval *)icmp->icmp_data;
	*(unsigned long *)((unsigned char *)icmp->icmp_data + sizeof(struct timeval)) 
		= pthread_self();// tid's length is bigger than icmp_id,so put tid in data after timestamp.
    gettimeofday(tval,NULL);    /*记录发送时间*/
    icmp->icmp_cksum=cal_chksum( (unsigned short *)icmp,packsize); /*校验算法*/
    return packsize;
}

/*发送ICMP报文*/
void send_packet(int sockfd, char * sendpacket, struct sockaddr_in dest_addr)
{   
	int packetsize;
	int nsend = 0;
	while( nsend < MAX_SEND_TIMES)
	{      
		printf("send tid=%u\n", (unsigned short)pthread_self());
		nsend++;
    	packetsize=pack(nsend, sendpacket); /*设置ICMP报头*/
    	if( sendto(sockfd,sendpacket,packetsize,0,(struct sockaddr *)&dest_addr,sizeof(dest_addr) )<0  )
    	{       
			perror("sendto error");
        	continue;
    	}
  
	}
}

/*接收所有ICMP报文*/
void recv_packet(int sockfd, char * recvpacket, struct sockaddr_in from)
{       
	int n,from_len;
    extern int errno;
	int nreceived = 0;
	struct timeval recv_time;
		
    from_len = sizeof(from);
    while (nreceived < MAX_SEND_TIMES)
	{    
    	if((n=recvfrom(sockfd,recvpacket, PACKET_SIZE, 0,
        	(struct sockaddr *)&from,&from_len)) <0)
        {   
			if(errno == EWOULDBLOCK || errno== EAGAIN )
			{
				printf("recvfrom Timeout!!!! %u\n", pthread_self());
				pthread_exit(NULL);
			}    
        }
				
       /*记录接收时间*/		
		gettimeofday(&recv_time,NULL);
				
        if (1 == unpack(recv_time, recvpacket, n, from))
		{
			printf(" find  %u\n", (unsigned short)pthread_self());
			nreceived++;
		}
		else
			printf(" not find\n");
	}

}
/*剥去ICMP报头*/
int unpack(struct timeval tvrecv, char *buf,int len, struct sockaddr_in from)
{    
	int iphdrlen;
	struct ip *ip;
	struct icmp *icmp;
	struct timeval *tvsend;
	double rtt;
		
    ip=(struct ip *)buf;
    iphdrlen=ip->ip_hl<<2;    /*求ip报头长度,即ip报头的长度标志乘4*/
    icmp=(struct icmp *)(buf+iphdrlen);  /*越过ip报头,指向ICMP报头*/
    len-=iphdrlen;            /*ICMP报头及ICMP数据报的总长度*/
    if( len<8)                /*小于ICMP报头长度则不合理*/
    {     
		  printf("ICMP packets\'s length is less than 8\n");
          return -1;
    }
	printf("unpack  tid=%u icmpid=%u ", (unsigned short)pthread_self(),icmp->icmp_id);
    /*确保所接收的是我所发的的ICMP的回应*/
    if( (icmp->icmp_type==ICMP_ECHOREPLY) 
		&& (icmp->icmp_id==(unsigned short)pthread_self()) 
		&& *(unsigned long *)((unsigned char *)icmp->icmp_data + sizeof(struct timeval)) == pthread_self())
    {     
		tvsend=(struct timeval *)icmp->icmp_data;
        tv_sub(&tvrecv,tvsend);  /*接收和发送的时间差*/
        rtt=tvrecv.tv_sec*1000+(float)tvrecv.tv_usec/1000;  /*以毫秒为单位计算rtt*/
        /*显示相关信息*/
        printf("%d byte from %s: icmp_seq=%u id= %u ttl=%d rtt=%.3f ms  ",
        	len, inet_ntoa(from.sin_addr),
            icmp->icmp_seq, icmp->icmp_id,
            ip->ip_ttl, rtt);
		strcpy(host[host_num], inet_ntoa(from.sin_addr));
		host_num ++;
			return 1;
    }
    else {
		printf(" unpack fail %u", (unsigned short)pthread_self());  
		return -1;
	}
}


int main(int argc,char *argv[])
{    
	int s = 0;
	int ip_num = 0;
	int i = 0;
	pthread_t * ntid;
	find_end_start_addr("eth0_rename");
	printf("%u %u\n",start_addr, end_addr);
			
    if( (protocol=getprotobyname("icmp") )==NULL)
    {      
			perror("getprotobyname");
        exit(1);
    }
    setuid(getuid());

  /*是ip地址*/
	ip_num = htonl(end_addr) - htonl(start_addr) + 1;
	printf("%d", ip_num);
	pthread_mutex_init(&lock, NULL);
	ntid = (pthread_t *)malloc(sizeof(pthread_t) * ip_num + 1);
		
	pthread_mutex_lock(&lock);		
	while (htonl(start_addr) <= htonl(end_addr))
	{			
		printf("start thread");
		pthread_create(&(ntid[i]), NULL, find_host, (void *)&start_addr);
		pthread_mutex_lock(&lock);
		start_addr = ntohl(htonl(start_addr) + 1);
		i++;
	}
	pthread_mutex_unlock(&lock);
	pthread_mutex_destroy(&lock);
	//pthread_create(&ntid2, NULL, find_host, (void *)&inaddr2);
	for (i = 0; i < ip_num; i++)
	{
		while(1)
		{			
			s = pthread_tryjoin_np(ntid[i], NULL);
			if (s != 0) {
				printf(".");
				usleep(1000);
			}
			else break;			
		}
	}
		
	free(ntid);
	for (i = 0; i < host_num; i++)
		printf("%s \n", host[i]);
    return 0;

}
/*两个timeval结构相减*/
void tv_sub(struct timeval *out,struct timeval *in)
{   
    if( (out->tv_usec-=in->tv_usec)<0)
    {
         --out->tv_sec;
         out->tv_usec+=1000000;
    }
    out->tv_sec-=in->tv_sec;
}
void *find_host(void *  arg)
{
	int sockfd;
	unsigned long ip ;
	tv.tv_sec = 0;
	tv.tv_usec = 100000;
	struct sockaddr_in from;
	char sendpacket[PACKET_SIZE];
	char recvpacket[PACKET_SIZE];
	ip = *(unsigned long *)arg;
	struct sockaddr_in present_addr;
	if( (sockfd=socket(AF_INET,SOCK_RAW,protocol->p_proto) )<0)
	{	      
		perror("socket error");
    	exit(1);
	}
	//fcntl(sockfd ,F_SETFL, O_NONBLOCK);         //非阻塞
	/*扩大套接字接收缓冲区到50K这样做主要为了减小接收缓冲区溢出的
      的可能性,若无意中ping一个广播地址或多播地址,将会引来大量应答*/
	setsockopt(sockfd,SOL_SOCKET,SO_RCVBUF,&size,sizeof(size) );
	if(setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv))<0){
		printf("socket option  SO_RCVTIMEO not support\n");
		return (void *)-1;	
	}
	bzero(&present_addr,sizeof(present_addr));
	present_addr.sin_family=AF_INET;
	present_addr.sin_addr.s_addr = ip;
	pthread_mutex_unlock(&lock);

	printf("PING (%s): %d bytes data in ICMP packets.\n",
                    inet_ntoa(present_addr.sin_addr),ICMP_DATA_LEN);
	send_packet(sockfd, sendpacket, present_addr);
	recv_packet(sockfd, recvpacket, from);
	close(sockfd);
}
void find_end_start_addr(char * interface)
{
	int fd;
	struct ifreq ifr;
	unsigned long mask;
	unsigned long this_ip;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family  = AF_INET;
	strncpy(ifr.ifr_name, interface ,IFNAMSIZ - 1);
	ioctl(fd, SIOCGIFADDR, &ifr);
	this_ip = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
	ioctl(fd, SIOCGIFNETMASK, &ifr);
	mask = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
	mask = 0xffffff;// 掩码可以自动获取，但是由于程序线程数量限制（猜测大约300）不能使用更多线程，所以人为规定掩码为255.255.255.0
	start_addr = this_ip & mask;
	end_addr = start_addr | (~mask);

	close(fd);
}
/*------------- The End -----------*/
