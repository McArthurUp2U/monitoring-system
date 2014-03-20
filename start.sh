#/bin/bash
print_help()
{
	echo 'start.sh -i  <ip> [-s <seconds>][-c]
	            [-p <port>][-r <procotols>]
	 Usage:\n"
	   -i <file.pcap|device>     | Specify a pcap file to read packets from or a device for live capture
	   -f <BPF filter>           | Specify a BPF filter for filtering selected traffic\n
	   -s <duration>             | Maximum capture duration in seconds (live traffic capture only)\n
	   -p <file>.protos          | Specify a protocol file (eg. protos.txt)\n
	   -l <num loops>            | Number of detection loops (test only)\n
	   -d                        | Disable protocol guess and use only DPI\n
	   -t                        | Dissect GTP tunnels\n
	   -h                        | This help\n
	   -v                        | Verbose 'unknown protocol' packet print\n");'
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
