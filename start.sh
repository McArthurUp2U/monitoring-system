#/bin/bash
print_help()
{
<<<<<<< HEAD:start.sh
	echo 'start.sh [-i <ip>] [-s <seconds>][-c]
	 [-p <port>][-r <procotols>] [l] 
Usage:
	-i <ip>                   | Specify a ip that comes into to be denied.
	-s <seconds>              | Statistics refresh seconds
	-p <port>                 | Specify a port comes into to be denied.
	-l                        | List protocols index number
	-c                        | Cancel port and ip deny. 
	-r  <procotols>]          | Disable procotols .
	-h                        | This help
	-v                        | Verbose statistics '
}
trap 'if test ! -z $a ; then  kill -4 $a;exit ; else iptables -D INPUT -p tcp -j QUEUE ;fi' 2
while getopts ":hs:i:cp:r:v:l" opt
=======
	echo 'start.sh -i  <ip> [-s <seconds>][-c]
	            [-p <port>][-r <procotols>] 
	 Usage:\n"
	   -i <ip>                   | Specify a ip that comes into to be denied.
	   -s <seconds>              | Statistics refresh seconds
	   -p <port>                 | Specify a port comes into to be denied.
	   -l <num loops>            | Number of detection loops (test only)\n
	   -c                        | Cancel port and ip deny. 
	   -r                        | Disable procotols .
	   -h                        | This help\n
	   -v                        | Verbose statistics '
}
trap 'if test ! -z $a ; then  kill -4 $a;exit ; else iptables -D INPUT -p tcp -j QUEUE ;fi' 2
while getopts ":hs:i:cp:r:v:" opt
>>>>>>> origin/master:start.sh
do
	case $opt in 
	h) print_help ;;
	s) ./statistics -i eth1 &
		a=`ps -ef|grep statistics |grep -v grep |awk '{print $2}'`
		echo $a
		while [ ture ]
		do
			kill -2 $a
			sleep $OPTARG
		done;;
	i) ./netfilter/nf_user -d $OPTARG;;
	p) ./netfilter/nf_user -p $OPTARG;;
	c) ./netfilter/nf_user;;
<<<<<<< HEAD:start.sh
	l) cat ./protocols;;

	r) modprobe ip_queue;iptables -I INPUT -p tcp -j QUEUE ; ./pcapReader -i packet_cache & ./ipq $OPTARG;;
=======
	r) iptables -I INPUT -p tcp -j QUEUE ; ./pcapReader -i packet_cache & ./ipq $OPTARG;;
>>>>>>> origin/master:start.sh
	v) ./statistics -i eth1 -v &
		a=`ps -ef|grep statistics |grep -v grep |awk '{print $2}'`
        echo $a
        while [ ture ]
        do
            kill -2 $a
            sleep $OPTARG
        done;;

	*) echo noo;;
	esac
done	
