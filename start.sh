#/bin/bash
print_help()
{
	echo "help func"
}
trap 'if test ! -z $a ; then  kill -4 $a;exit ; else iptables -D INPUT -p tcp -j QUEUE ;fi' 2
while getopts ":hs:i:cp:r:" opt
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
	*) echo noo;;
	esac
done	
