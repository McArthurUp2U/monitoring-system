#/bin/bash
print_help()
{
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
	r) iptables -I INPUT -p tcp -j QUEUE ; ./pcapReader -i packet_cache & ./ipq $OPTARG;;
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
