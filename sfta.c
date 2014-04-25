#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <float.h>
#include <time.h> 
#include <sys/time.h>

#include "utils.h"
#include "lsrp.h"
#include "lsrp-net.h"

#define SEGMENT_LEN		64
#define TIME_OUT		5
#define MAX_BUF_LEN	4096

unsigned long sender_id, receiver_id;
char *filepath;
int snd = 0;

int closock;

// sending paclet to our edge router
void *sender(void *arg)
{
	char segbuf[SEGMENT_LEN];
	char rbuf[MAX_BUF_LEN], sbuf[MAX_BUF_LEN];
	struct lsrp_pkt_segm segm;
	int fd = open(filepath, O_RDONLY);
	
	segm.src_id = sender_id;
	segm.dst_id = receiver_id;
	segm.ttl = 10;
	segm.seqno = 0;
	
	while(1)
	{
		usleep(30000);
		
		int len = read(fd, segbuf, SEGMENT_LEN);
		segm.len = len;
		segm.seqno++;

retry:		
		lsrp_pkt_fill(sbuf, sender_id, LSRP_PKT_SEGM, sizeof(struct lsrp_pkt_segm), (void *)&segm);
		memcpy(sbuf + LSRP_HDR_SIZE + sizeof(struct lsrp_pkt_segm), segbuf, len);
		
		printf("%llu sent [%lu bytes]...\n", segm.seqno, segm.len);
		udp_snd(get_ip_id(sender_id), get_cliport_id(sender_id), sbuf, LSRP_HDR_SIZE + sizeof(struct lsrp_pkt_segm) + len);
		
		if(udp_rcv_nobind(closock, rbuf, MAX_BUF_LEN, NULL) < 0)
			goto retry;
		
		// wait for ack befre we proceed with next packet
		struct lsrp_pkt_segm *ackseg = lsrp_pkt_get_data(rbuf);
		if(ackseg->len == -1 && ackseg->seqno == segm.seqno)
		{
			printf("%llu acked...\n", segm.seqno);
			if(len == 0) break;
			continue;
		} else {
			goto retry;
		}
		
		if(len == 0) break;
	}
	
	close(fd);
	return NULL;
}

int load_config()
{
	char buf[65535];
	char lookup[256];
	int i, j;
	
	int fd = open("./setup.cfg", O_RDONLY);
	read(fd, buf, 65535);
	close(fd);
	
	int n;
	sscanf(buf, "count: %d", &n);
	router_count = n;
	
	names = (char **)malloc(sizeof(char *) * n);
	ips = (char **)malloc(sizeof(char *) * n);
	ports = malloc(sizeof(int) * n);
	cliports = malloc(sizeof(int) * n);
	cloports = malloc(sizeof(int) * n);
	adj_mat = malloc(sizeof(double *) * n);
	link_mat = malloc(sizeof(int *) * n);
	next_router = malloc(sizeof(int) * n);
	memset(next_router, -1, n);									  
	last_helo = malloc(sizeof(unsigned long long) * n);
	last_advr_ts = malloc(sizeof(unsigned long long) * n);
	last_advr_seqno = malloc(sizeof(unsigned long long) * n);
	bzero(last_helo, sizeof(unsigned long long) * n);
	bzero(last_advr_ts, sizeof(unsigned long long) * n);
	bzero(last_advr_seqno, sizeof(unsigned long long) * n);
	for(i = 0; i < n; i++)
	{
		names[i] = (char *)malloc(256);
		ips[i] = (char *)malloc(256);
		adj_mat[i] = malloc(sizeof(double) * n);
		link_mat[i] = malloc(sizeof(int) * n);
		
		bzero(adj_mat[i], sizeof(double) * n);
		bzero(link_mat[i], sizeof(int) * n);
		bzero(names[i], sizeof(char) * 256);
		bzero(ips[i], sizeof(char) * 256);
	}
	
	for(i = 0; i < n; i++)
	{
		char *lead;
		sprintf(lookup, "router%d:", i);
		if(NULL == (lead = strstr(buf, lookup)))
		{
			fprintf(stderr, "%s expected, exiting...\n", lookup);
			goto error;
		}
		char name[256], ip[256];
		int port, cli, clo, idx;
		sscanf(lead, "router%d:\t%s\t%s\t%d\t%d\t%d", &idx, name, ip, &port, &cli, &clo);
		
		ports[i] = port;
		cliports[i] = cli;
		cloports[i] = clo;
		strcpy(names[i], name);
		strcpy(ips[i], ip);		
	}
	
	for(i = 0; i < n * n; i++)
	{
		char *lead;
		int from, to, idx;
		sprintf(lookup, "link%d:", i);
		if(NULL == (lead = strstr(buf, lookup)))
		{
			break;
		}
		
		sscanf(lead, "link%d:\t%d\t%d", &idx, &from, &to);
		if(from >= n || from < 0 || to >= n || to < 0)
		{
			fprintf(stderr, "invalid router index (%d, %d), exiting...\n", from, to);
			goto error;
		}
		link_mat[from][to] = 1;
		link_mat[to][from] = 1;
	}
	
	return n;
	
error:
	return -1;
}

// receiving packet from our edge router
void *receiver(void *arg)
{
	char segbuf[SEGMENT_LEN];
	char rbuf[MAX_BUF_LEN], sbuf[MAX_BUF_LEN];
	struct lsrp_pkt_segm segmack;
	int fd = open(filepath, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	
	segmack.src_id = receiver_id;
	segmack.dst_id = sender_id;
	segmack.ttl = 10;
	segmack.len = -1;
	
	unsigned long long last_seqno = 0;
	
	while(1)
	{
		if(udp_rcv_nobind(closock, rbuf, MAX_BUF_LEN, NULL) < 0)
			continue;
		
		struct lsrp_pkt_segm *segm = lsrp_pkt_get_data(rbuf);
		
		printf("%llu received [%lu bytes]...", segm->seqno, segm->len);
		
		// if we have already seen it, just send ack
		if(last_seqno >= segm->seqno)
			goto send_ack;
		
		write(fd, rbuf + LSRP_HDR_SIZE + sizeof(struct lsrp_pkt_segm), segm->len);
		
send_ack:
		// send ack
		last_seqno = segm->seqno;
		segmack.seqno = segm->seqno;
		printf("acked\n", segm->seqno);
		lsrp_pkt_fill(sbuf, receiver_id, LSRP_PKT_SEGM, sizeof(struct lsrp_pkt_segm), (void *)&segmack);
		udp_snd(get_ip_id(receiver_id), get_cliport_id(receiver_id), sbuf, LSRP_HDR_SIZE + sizeof(struct lsrp_pkt_segm));
		
		if(segm->len == 0) break;
	}
	
	close(fd);
	return NULL;
}

int main(int argc, char **argv)
{
	if(argc != 5)
	{
		printf("Usage:\n\t%s <snd|rcv> <sender> <receiver> <filepath>\n", argv[0]);
		exit(-1);
	}
	
	router_count = load_config(names, ips, ports, cliports, cloports, adj_mat, link_mat);
	
	sender_id = atol(argv[2]);
	receiver_id = atol(argv[3]);
	filepath = argv[4];
	if(strcmp("snd", argv[1]) == 0)
	{
		snd = 1;
	} else if(strcmp("rcv", argv[1]) == 0) {
		snd = 0;
	} else {
		printf("Usage:\n\t%s <snd|rcv> <sender> <receiver> <filepath>\n", argv[0]);
		exit(-1);
	}
	
	printf("starting %s %s from %s to %s...\n", (snd ? "sending" : "receiving"), filepath, get_ip_id(sender_id), get_ip_id(receiver_id));
	
	closock = udp_sock_bind(get_cloport_id((snd ? sender_id : receiver_id)));
	
	struct timeval tv;
	tv.tv_sec = TIME_OUT;
	tv.tv_usec = 0; 
	setsockopt(closock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval));
	
	if(snd)
	{
		pthread_t t_sender;
		pthread_create(&t_sender, NULL, sender, NULL);
		pthread_join(t_sender, NULL);
	} else {
		pthread_t t_receiver;
		pthread_create(&t_receiver, NULL, receiver, NULL);	
		pthread_join(t_receiver, NULL);
	}
	
	close(closock);
	return 0;
}
