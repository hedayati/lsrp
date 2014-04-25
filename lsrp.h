#ifndef __LSRP_H__
#define __LSRP_H__

#define DATA_MAX_LEN	4096
#define MAX_ROUTER_COUNT	256
int router_count;
char **names, **ips;
int *ports, *cliports, *cloports, **link_mat;
double **adj_mat;
											  
int *next_router;											  
unsigned long long *last_helo;
unsigned long long *last_advr_ts;
unsigned long long *last_advr_seqno;

#define get_name_id(id)	names[id]
#define get_ip_id(id)	ips[id]
#define get_port_id(id)	ports[id]
#define get_cliport_id(id)	cliports[id]
#define get_cloport_id(id)	cloports[id]

#define LSRP_PKT_PING  0
#define LSRP_PKT_HELO  1
#define LSRP_PKT_ADVR  2
#define LSRP_PKT_NACQ  3

#define LSRP_PKT_SEGM  4

struct lsrp_pkt_hdr
{
	unsigned long router_id;
	unsigned short pkt_type;
	unsigned long checksum;
	unsigned long len;
};

#define PING_TYPE_PING	0
#define PING_TYPE_PONG	1

struct lsrp_pkt_ping
{
	unsigned short type;
	unsigned long long timestamp;
};

struct lsrp_pkt_helo
{
};

struct lsrp_pkt_advr
{
	unsigned long adv_id;
	unsigned long ttl;
	unsigned long long seqno;
	unsigned long long timestamp;
	double weights[MAX_ROUTER_COUNT];
};

#define NACQ_BE_NEIGHBOR_REQ	0
#define NACQ_BE_NEIGHBOR_ACC	1
#define NACQ_BE_NEIGHBOR_REF	2
#define NACQ_CEASE_NEIGHBOR		3
struct lsrp_pkt_nacq
{
	unsigned short type;
};

struct lsrp_pkt_segm
{
	unsigned long src_id;
	unsigned long dst_id;
	unsigned long ttl;
	unsigned long len;				// -1 to show ACK
	unsigned long long seqno;		// also used for ACK
};
	

#define LSRP_HDR_SIZE sizeof(struct lsrp_pkt_hdr)

unsigned long get_checksum(char *str, unsigned long len)
{
	unsigned long csum = 0;
	int i = 0;
	for(; i < len; i++)
	{
		csum += str[i];
	}
	
	return csum;
}

void lsrp_pkt_fill(void *buf, unsigned long rid, unsigned short typ, unsigned long len, void *data)
{
	struct lsrp_pkt_hdr hdr;
	hdr.router_id = rid;
	hdr.pkt_type = typ;
	hdr.checksum = get_checksum((char *) data, len);
	hdr.len = len;
	
	memcpy(buf, &hdr, LSRP_HDR_SIZE);
	memcpy(buf + LSRP_HDR_SIZE, data, len);
}

struct lsrp_pkt_hdr *lsrp_pkt_get_hdr(void *buf)
{
	return (struct lsrp_pkt_hdr *)buf;
}

void *lsrp_pkt_get_data(void *buf)
{
	return (void *) (((unsigned long) buf) + LSRP_HDR_SIZE);
}

#define PING_ALPHA		0.2
#define PING_INTERVAL	500000

#define HELO_THRESHOLD	3000
#define HELO_INTERVAL	700000

#define NACQ_INTERVAL	3000000

#define DEBG_INTERVAL	30000000

#define DIJK_INTERVAL	3000000

#define ADVR_INTERVAL	3000000
#define ADVR_TTL		10
#define ADVR_THRESHOLD	30000

#define LOSS_PROB		0.8
#define CRPT_PROB		0.3

#endif
