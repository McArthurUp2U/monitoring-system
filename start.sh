#/bin/bash
print_help()
{
	echo './start.sh [-i <ip>] [-s <device>][-c]
	   [-p <port>][-r <procotols>] [l] [t <seconds>] [a]
Usage:
	-a                        | show ethernet device
	-i <ip>                   | Specify a ip that comes into to be denied.
	-s <device>               | Statistics of NIC device 
	-p <port>                 | Specify a port comes into to be denied.
	-l                        | List protocols index number
	-c                        | Cancel port and ip deny. 
	-r  <procotols>]          | Disable procotols .
	-h                        | This help
	-v                        | Verbose statistics 
	-t <seconds>              | refresh time'
}
t=1
trap 'if test ! -z $a ; then  kill -4 $a  ;exit ; else iptables -D INPUT -p tcp -j QUEUE; kill -4 $b ;exit ;fi' 2
if test $# = 0 
then print_help
fi
while getopts ":afhs:i:clp:r:v:t:" opt
do
	case $opt in 
	a) /sbin/ifconfig|sed -n 'N;/eth/p';;
	t) t=$OPTARG;;
	h) print_help ;;
	s) ./statistics -i $OPTARG &
		a=`ps -ef|grep statistics |grep -v grep |awk '{print $2}'`
		echo $a
		while [ ture ]
		do
			kill -2 $a
			sleep $t
		done;;
	i) ./netfilter/nf_user -d $OPTARG;;
	p) ./netfilter/nf_user -p $OPTARG;;
	c) ./netfilter/nf_user;;
	l) less  ./protocols;;
	r) iptables -I INPUT -p tcp -j QUEUE ; ./pcapReader -i packet_cache & 
		b=`ps -ef|grep pcapReader |grep -v grep |awk '{print $2}'`
		echo $b
		./ipq $OPTARG ;;
	v) ./statistics -i $OPTARG -v &
		a=`ps -ef|grep statistics |grep -v grep |awk '{print $2}'`
        echo $a
        while [ ture ]
        do
            kill -2 $a
            sleep $t
        done;;
	f) ./icmp_host_find $2 $3;;

	*) echo bad options!!!;;
	esac
done	
