#ifndef _SHARE_H_
#define _SHARE_H_

static const int PktClassierPort = 5000;
static const int PktCapPort = 5006;
static const int ServPort=50000;
static const int FlowEndPort = 50009;
static const char *servaddress="127.0.0.1";
static const int num=1;
struct packet{
	u_int32_t type_flow;
	u_int16_t sport,dport;
	u_int32_t saddr,daddr;
	u_int32_t TcpOrUdp;
	u_int16_t packets, bytes;
};
struct RequestPkt{
	int nNumItems;
	struct packet Items[1];
};
#endif
