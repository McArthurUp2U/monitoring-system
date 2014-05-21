###Functions
Count protocols and flows
hosts find and traffic statistics in LAN
stop some  ip,port,procotol
###Usage
It is the implementation of my undergraduate Thesis.
It also can be a sample of netlink ,iptables ,ip_queue ,icmp and  nDPI.
###Environment
testing:
*kernel 2.6.28
*Fedora 10
###Do NOT forget:
modprobe ip_queue
insmod hook.ko
###Some bugs
can not run over 2 .sh in the same time
No configure scripts. maybe use autoconfig,automake in the future.
