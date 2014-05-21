INC=-I /home/wangs/monitoring-system/include/
LIB1=/home/wangs/monitoring-system/lib/libndpi.a -lpcap 
LIB2=-lipq
LIB3=-lpthread
FLAGS=-g -Wall
CC=gcc

all:pcapReader ipq statistic ./netfilter/hook.c icmp_host_find ht
	make -C ./netfilter
pcapReader:pcapReader.c Makefile ./libipq.c 
	$(CC) $(FLAGS) $(INC) pcapReader.c -o pcapReader $(LIB1)
statistic:statistics.c
	$(CC) $(FLAGS) $(INC) statistics.c -o statistics $(LIB1)
ipq:	
	$(CC) libipq.c -o ipq $(LIB2)
icmp_host_find: icmp_host_find.c
	$(CC) $(FLAGS) icmp_host_find.c -o icmp_host_find $(LIB3)
ht: hostTraffic.c
	$(CC) $(FLAGS) hostTraffic.c -o ht $(LIB1)
clean:
	rm ./pcapReader ./ipq ./netfilter/nf_user statistics ht icmp_host_find
	find -name '*.ko' -exec rm -f {} \;
	find -name '*.o' -exec rm -f {}  \;
	find -name '[Mm]odule*' -exec rm -f {} \;
	rm -f ./netfilter/hook.mod.c 
install:
	insmod ./netfilter/hook.ko
	modprobe ip_queue
uninstall: clean
	rmmod hook

.PHONY: all clean install uninstall
