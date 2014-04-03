#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <string.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <getopt.h>
#include "hook.h"

#define MAX_PAYLOAD 1024 /* maximum payload size*/

struct sockaddr_nl src_addr, dest_addr;
struct nlmsghdr *nlh = NULL;
struct iovec iov;
int sock_fd;
struct msghdr msg;
struct option longopts[] =
 {
   {"icmp",no_argument, NULL, 'i'},
   {"help",no_argument, NULL, 'h'},
   {"drop",required_argument, NULL, 'd'},
   {0,0,0,0}
  };

void print_help(char* str)
{
 fprintf(stderr,"%s --icmp(-i)\n",str);
 fprintf(stderr,"%s --drop(-d)\n",str);
 fprintf(stderr,"eg:\n%s -i -d 202.114.85.105\n",str);
}

void init_own(OWN** own)
{
 *own = (OWN*)malloc(sizeof(OWN));
 (*own)->icmp_off = 0;
 (*own)->drop_ip = 0; 
 (*own)->drop_port = -1;
}        

int main(int argc, char* argv[])
{
   int c;
   OWN* own = NULL;
   init_own(&own);

   while((c=getopt_long(argc, argv, "hid:p:", longopts, NULL))!=-1)   
    {
      switch(c)
       {
         case 'i':
          {
            own->icmp_off = 1;
            break;
          }
         case 'd':
          {
            own->drop_ip = inet_addr(optarg);
            break;
          }
		 case 'p':
          {
            own->drop_port = atoi(optarg);
            break;
          }
         case 'h':
           {
            print_help(argv[0]);
            return -1;
           }
        
         default:
          break;
       }

    }  
 
   sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_TEST);
   memset(&msg, 0, sizeof(msg));
   memset(&src_addr, 0, sizeof(src_addr));
   src_addr.nl_family = AF_NETLINK;
   src_addr.nl_pid = getpid(); /* self pid */
   src_addr.nl_groups = 0; /* not in mcast groups */
   bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));
   memset(&dest_addr, 0, sizeof(dest_addr));
   dest_addr.nl_family = AF_NETLINK;
   dest_addr.nl_pid = 0; /* For Linux Kernel */
   dest_addr.nl_groups = 0; /* unicast */
   

   nlh=(struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
   /* Fill the netlink message header */
   nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
   nlh->nlmsg_pid = getpid(); /* self pid */
   nlh->nlmsg_flags = 0;
   /* Fill in the netlink message payload */
   printf("%d, %d %d\n", own->icmp_off, own->drop_ip, own->drop_port);
   memcpy(NLMSG_DATA(nlh),own ,sizeof(OWN));

   iov.iov_base = (void *)nlh;
   iov.iov_len = nlh->nlmsg_len;
   msg.msg_name = (void *)&dest_addr;
   msg.msg_namelen = sizeof(dest_addr);
   msg.msg_iov = &iov;
   msg.msg_iovlen = 1;

   printf(" Sending message. ...\n");
   sendmsg(sock_fd, &msg, 0);
   
   memset(nlh,0,NLMSG_SPACE(MAX_PAYLOAD));

   close(sock_fd);
   free(own);
   return 0;
}
