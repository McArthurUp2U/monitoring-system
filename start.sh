#/bin/bash
print_help()
{
	echo "help func"
}
trap 'kill -4 $a;exit' 2
while getopts ":hs:" opt
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
	*) echo noo
	esac
done	

