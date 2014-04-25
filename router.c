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

#define DEBUG

#define ROUTER_PORT	get_port_id(local_id)
#define CLIENT_PORT	get_cliport_id(local_id)

#define MAX_BUF_LEN	4096

int clisock, rousock;
unsigned long local_id = 0;

unsigned int terminate = 0;

// Current timestamp
unsigned long long get_timestamp() {
	struct timeval te; 
	gettimeofday(&te, NULL);
	unsigned long long milliseconds = te.tv_sec * 1000LL + te.tv_usec / 1000;
	return milliseconds;
}

// Formwarding ES's data segments to next hop
void forward_segment(void *buf)
{
	struct lsrp_pkt_hdr *pkt_hdr = lsrp_pkt_get_hdr(buf);
	struct lsrp_pkt_segm *pkt_segm = lsrp_pkt_get_data(buf);
	
	// dropping the packet - failure emulation
	if(rand() % 100 < LOSS_PROB)
	{
		printf("losing...\n");
		return;
	}
	
	// corruptiong the packet - failure emulation
	if(rand() % 100 < CRPT_PROB)
	{
		printf("corrupting...\n");
		pkt_segm->len = -5;
	}
	
	if(pkt_segm->dst_id == local_id)
	{
		// deliver
		printf("deliver...\n");
		udp_snd(get_ip_id(local_id), get_cloport_id(local_id), buf, LSRP_HDR_SIZE + pkt_segm->len + sizeof(struct lsrp_pkt_segm));
	} else if(next_router[pkt_segm->dst_id] == -1) {
		// drop
		printf("drop...\n");
	} else {
		// forward
		unsigned long next_id = next_router[pkt_segm->dst_id];
		printf("forward to %s:%s...\n", get_name_id(next_id), get_ip_id(next_id));
		pkt_hdr->router_id = local_id;
		udp_snd(get_ip_id(next_id), get_port_id(next_id), buf, LSRP_HDR_SIZE + pkt_segm->len + sizeof(struct lsrp_pkt_segm));
	}
	
}

// processing received router advertisements
void process_advr(struct lsrp_pkt_advr *pkt_advr)
{
	int i;
	if(pkt_advr->adv_id == local_id) return;
	if(last_advr_seqno[pkt_advr->adv_id] >= pkt_advr->seqno)
	{
		if(last_advr_ts[pkt_advr->adv_id] > pkt_advr->timestamp)
		{
			return;
		}
	}
		
	last_advr_seqno[pkt_advr->adv_id] = pkt_advr->seqno;
	last_advr_ts[pkt_advr->adv_id] = get_timestamp();
	
	memcpy(adj_mat[pkt_advr->adv_id], pkt_advr->weights, router_count * sizeof(double));
	pkt_advr->ttl--;
	if(pkt_advr->ttl == 0) return;
	
	// Flooding the advertisement
	void *nbuf = malloc(LSRP_HDR_SIZE + sizeof(struct lsrp_pkt_advr));
	lsrp_pkt_fill(nbuf, local_id, LSRP_PKT_ADVR, sizeof(struct lsrp_pkt_advr), (void *)pkt_advr);
	for(i = 0; i < router_count; i++)
	{
		if(link_mat[local_id][i] == 0) continue;
		if(adj_mat[local_id][i] == 0) continue;
		udp_snd(get_ip_id(i), get_port_id(i), nbuf, LSRP_HDR_SIZE + sizeof(struct lsrp_pkt_advr));
	}
	free(nbuf);
	
}

// connection to end systems
void *router(void *ptr)
{
	char buf[MAX_BUF_LEN];
	while(1)
	{
		if(terminate) break;
		usleep(1000);
		
		bzero(buf, MAX_BUF_LEN);
		if(udp_rcv_nobind(clisock, buf, MAX_BUF_LEN, NULL) < 0)
		{
			continue;
		}
		
		struct lsrp_pkt_hdr *hdr = lsrp_pkt_get_hdr(buf);
		if(hdr->checksum != get_checksum(lsrp_pkt_get_data(buf), hdr->len))
		{
			fprintf(stderr, "corrupted packet, skipping...\n");
			continue;
		}
		
		if(hdr->pkt_type != LSRP_PKT_SEGM)
		{
			printf("invalid packet type...\n");
			continue;
		}
		
		forward_segment(buf);
	}
}

// looking for incoming packets and handling them
void *incoming(void *ptr)
{
	char buf[MAX_BUF_LEN];
	while(1)
	{
		if(terminate) break;
		usleep(1000);
		
		bzero(buf, MAX_BUF_LEN);
		if(udp_rcv_nobind(rousock, buf, MAX_BUF_LEN, NULL) < 0)
		{
			continue;
		}
		
		struct lsrp_pkt_hdr *hdr = lsrp_pkt_get_hdr(buf);
		
		// checking for packet corruption
		if(hdr->checksum != get_checksum(lsrp_pkt_get_data(buf), hdr->len))
		{
			fprintf(stderr, "corrupted packet...\n");
			continue;
		}
		
		switch(hdr->pkt_type)
		{
			case LSRP_PKT_PING:
				// if we receive a ping, respond immediately with a pong
				if(((struct lsrp_pkt_ping *) lsrp_pkt_get_data(buf))->type == PING_TYPE_PING)
				{
					struct lsrp_pkt_ping pkt_ping_rsp;
					pkt_ping_rsp.type = PING_TYPE_PONG;
					pkt_ping_rsp.timestamp = ((struct lsrp_pkt_ping *) lsrp_pkt_get_data(buf))->timestamp;
					void *nbuf = malloc(LSRP_HDR_SIZE + sizeof(struct lsrp_pkt_ping));
					lsrp_pkt_fill(nbuf, local_id, LSRP_PKT_PING, sizeof(struct lsrp_pkt_ping), (void *)&pkt_ping_rsp);
					udp_snd(get_ip_id(hdr->router_id), get_port_id(hdr->router_id), nbuf, LSRP_HDR_SIZE + sizeof(struct lsrp_pkt_ping));
					free(nbuf);
				} else {
					// estimating the cost of the link
					unsigned long long diff = (get_timestamp() - ((struct lsrp_pkt_ping *) lsrp_pkt_get_data(buf))->timestamp);
					//printf("pong from %s %llu ms\n", get_ip_id(hdr->router_id), diff);
					adj_mat[local_id][hdr->router_id] = PING_ALPHA * adj_mat[local_id][hdr->router_id] + (1 - PING_ALPHA) * diff;
				}
				break;
			case LSRP_PKT_HELO:
				// last time we heared from this router
				last_helo[hdr->router_id] = get_timestamp();
				//printf("helo from %s at %llu\n", get_ip_id(hdr->router_id), last_helo[hdr->router_id]);
				break;
			case LSRP_PKT_ADVR:
				process_advr((struct lsrp_pkt_advr *)lsrp_pkt_get_data(buf));
				break;
			case LSRP_PKT_NACQ:
				// if someone is requesting to connect...
				if(((struct lsrp_pkt_nacq *) lsrp_pkt_get_data(buf))->type == NACQ_BE_NEIGHBOR_REQ)
				{
					struct lsrp_pkt_nacq pkt_nacq_rsp;
					pkt_nacq_rsp.type = NACQ_BE_NEIGHBOR_ACC;
					void *nbuf = malloc(LSRP_HDR_SIZE + sizeof(struct lsrp_pkt_nacq));
					lsrp_pkt_fill(nbuf, local_id, LSRP_PKT_NACQ, sizeof(struct lsrp_pkt_nacq), (void *)&pkt_nacq_rsp);
					udp_snd(get_ip_id(hdr->router_id), get_port_id(hdr->router_id), nbuf, LSRP_HDR_SIZE + sizeof(struct lsrp_pkt_nacq));
					free(nbuf);
					
					adj_mat[local_id][hdr->router_id] = 1;
					printf("connected to %s:%s...\n", get_name_id(hdr->router_id), get_ip_id(hdr->router_id));
				}
				if(((struct lsrp_pkt_nacq *) lsrp_pkt_get_data(buf))->type == NACQ_BE_NEIGHBOR_ACC)
				{
					adj_mat[local_id][hdr->router_id] = 1;
					printf("connected to %s:%s...\n", get_name_id(hdr->router_id), get_ip_id(hdr->router_id));
				}
				break;
			case LSRP_PKT_SEGM:
				forward_segment(buf);
				break;
			default:
				printf("invalid packet type...\n");
				break;
		}		
	}
	return NULL;
}

// Periodically send ping messages
// upon receiving response (pong) the cost of link will be re-estimated
void *ping(void *ptr)
{
	int i;
	struct lsrp_pkt_ping pkt_ping;
	pkt_ping.type = PING_TYPE_PING;
	while(1)
	{
		if(terminate) break;
		usleep(PING_INTERVAL);
		
		void *buf = malloc(LSRP_HDR_SIZE + sizeof(struct lsrp_pkt_ping));
		for(i = 0; i < router_count; i++)
		{
			if(link_mat[local_id][i] == 0) continue;
			if(adj_mat[local_id][i] == 0) continue;
			
			bzero(buf, LSRP_HDR_SIZE + sizeof(struct lsrp_pkt_ping));
			pkt_ping.timestamp = get_timestamp();
			lsrp_pkt_fill(buf, local_id, LSRP_PKT_PING, sizeof(struct lsrp_pkt_ping), (void *)&pkt_ping);
			usleep(1564 * (rand() % (i + 2)));
			udp_snd(get_ip_id(i), get_port_id(i), buf, LSRP_HDR_SIZE + sizeof(struct lsrp_pkt_ping));
		}
		free(buf);
	}
	return NULL;
}

// sending hello heartbeat message periodically
void *helo(void *ptr)
{
	int i;
	while(1)
	{
		if(terminate) break;
		usleep(HELO_INTERVAL);
		
		void *buf = malloc(LSRP_HDR_SIZE);
		for(i = 0; i < router_count; i++)
		{
			if(link_mat[local_id][i] == 0) continue;
			if(adj_mat[local_id][i] == 0) continue;
			
			bzero(buf, LSRP_HDR_SIZE);
			lsrp_pkt_fill(buf, local_id, LSRP_PKT_HELO, 0, NULL);
			udp_snd(get_ip_id(i), get_port_id(i), buf, LSRP_HDR_SIZE);
		}
		free(buf);
		
		for(i = 0; i < router_count; i++)
		{
			if(last_helo[i] == 0) continue;
			
			// we haven't heared from this router in a while...
			// link or node failure
			if(get_timestamp() - last_helo[i] > HELO_THRESHOLD)
			{
				if(adj_mat[local_id][i])
				{
					printf("link to %s:%s failed...\n", get_name_id(i), get_ip_id(i));
				}
				adj_mat[local_id][i] = 0;
				last_helo[i] == 0;
			}
		}
	}
	return NULL;
}


// Link-state Advertisement
void *advr(void *ptr)
{
	int i, j;
	unsigned long long seqno = 0;
	struct lsrp_pkt_advr pkt_advr;
	while(1)
	{
		if(terminate) break;
		usleep(ADVR_INTERVAL);
		
		void *buf = malloc(LSRP_HDR_SIZE + sizeof(struct lsrp_pkt_advr));
		for(i = 0; i < router_count; i++)
		{
			if(i == local_id) continue;
			
			if(link_mat[local_id][i] == 0) continue;
			if(adj_mat[local_id][i] == 0) continue;
			
			bzero(buf, LSRP_HDR_SIZE + sizeof(struct lsrp_pkt_advr));
			pkt_advr.adv_id = local_id;
			pkt_advr.seqno = ++seqno;
			pkt_advr.ttl = ADVR_TTL;			
			pkt_advr.timestamp = get_timestamp();
			memcpy(pkt_advr.weights, adj_mat[local_id], router_count * sizeof(double));
			lsrp_pkt_fill(buf, local_id, LSRP_PKT_ADVR, sizeof(struct lsrp_pkt_advr), (void *)&pkt_advr);
			udp_snd(get_ip_id(i), get_port_id(i), buf, LSRP_HDR_SIZE + sizeof(struct lsrp_pkt_advr));
		}
		free(buf);
		
		// Checking that we are hearing advertisement from all other router
		// If not, remove their state from our map of network
		for(i = 0; i < router_count; i++)
		{
			if(i == local_id) continue;
			
			if(get_timestamp() - last_advr_ts[i] > ADVR_THRESHOLD)
			{
				int first = 0;
				for(j = 0; j < router_count; j++)
				{
					first += (adj_mat[i][j] != 0);
					adj_mat[i][j] = 0;
				}
				if(first)
				{
					printf("advertise delay from %s:%s beyond threshold...\n", get_name_id(i), get_ip_id(i));
				}
			}
		}
	}
	return NULL;
}

// Neighbour acquisition looks for chance to connect to routers that we 
// have a link with
void *nacq(void *ptr)
{
	int i;
	struct lsrp_pkt_nacq pkt_nacq;
	while(1)
	{
		if(terminate) break;
		usleep(NACQ_INTERVAL);
		
		void *buf = malloc(LSRP_HDR_SIZE + sizeof(struct lsrp_pkt_nacq));
		for(i = 0; i < router_count; i++)
		{
			if(link_mat[local_id][i] == 0) continue;
			if(adj_mat[local_id][i] != 0) continue;
			
			bzero(buf, LSRP_HDR_SIZE + sizeof(struct lsrp_pkt_nacq));
			pkt_nacq.type = NACQ_BE_NEIGHBOR_REQ;
			lsrp_pkt_fill(buf, local_id, LSRP_PKT_NACQ, sizeof(struct lsrp_pkt_nacq), (void *)&pkt_nacq);
			udp_snd(get_ip_id(i), get_port_id(i), buf, LSRP_HDR_SIZE + sizeof(struct lsrp_pkt_nacq));
		}
		free(buf);
	}
	return NULL;
}

// Printing the debugging info (network map + forwarding table)
void *debug(void *ptr)
{
	int i;
	while(1)
	{
		if(terminate) break;
		usleep(DEBG_INTERVAL);
		
		printf("\nLOCAL MAP:\n");
		print_mat(adj_mat, router_count, router_count);
		
		printf("\nROUTING TABLE:\n");
		for(i = 0; i < router_count; i++)
		{
			printf("\t-> To %s:\t", get_name_id(i));
			if(i == local_id)
			{
				printf("SELF\n");
			}
			else
			{
				printf("%s\n", (next_router[i] == -1) ? "UNKNOWN" : get_name_id(next_router[i]));
			}
		}
		printf("\n");
		
		printf("---------------------------------------------------\n");
	}
	return NULL;
}

// Calling dikjestra algorithm
void *dij(void *ptr)
{
	int i;
	int *prev = malloc(router_count * sizeof(int));
	while(1)
	{
		if(terminate) break;
		usleep(DIJK_INTERVAL);
		
		dijkstra(router_count, local_id, adj_mat, prev);
		
		// updating the next hop table
		for(i = 0; i < router_count; i++)
		{
			next_router[i] = dijkstra_getnext(i, prev);
		}
	}
	free(prev);
	return NULL;
}

// load configuration form config.cfg in the same directory
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

int main(int argc, char **argv)
{
	int router_count = load_config(names, ips, ports, cliports, cloports, adj_mat, link_mat);
	
	if(argc != 2)
	{
		printf("Usage:\n\t%s <router-id>\n", argv[0]);
		exit(-1);
	}
	
	local_id = atol(argv[1]);
	printf("starting router %lu:%s at %s:%d...\n", local_id, get_name_id(local_id), get_ip_id(local_id), get_port_id(local_id));
	
	clisock = udp_sock_bind(CLIENT_PORT);
	rousock = udp_sock_bind(ROUTER_PORT);
	
	// Setting the socket timeout
	struct timeval tv;
	tv.tv_sec = 5;		// 5s
	tv.tv_usec = 0; 
	setsockopt(rousock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval));
	
	tv.tv_sec = 5;
	tv.tv_usec = 0; 
	setsockopt(clisock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval));
	
	pthread_t t_incoming;
	pthread_create(&t_incoming, NULL, incoming, NULL);
	
	pthread_t t_ping;
	pthread_create(&t_ping, NULL, ping, NULL);
	
	pthread_t t_helo;
	pthread_create(&t_helo, NULL, helo, NULL);
	
	pthread_t t_advr;
	pthread_create(&t_advr, NULL, advr, NULL);
	
	pthread_t t_nacq;
	pthread_create(&t_nacq, NULL, nacq, NULL);
	
	pthread_t t_debug;
	pthread_create(&t_debug, NULL, debug, NULL);
	
	pthread_t t_dij;
	pthread_create(&t_dij, NULL, dij, NULL);
	
	pthread_t t_router;
	pthread_create(&t_router, NULL, router, NULL);
	
	//terminate = 1;
	
	pthread_join(t_incoming, NULL);
	pthread_join(t_ping, NULL);
	pthread_join(t_helo, NULL);
	pthread_join(t_advr, NULL);
	pthread_join(t_nacq, NULL);
	pthread_join(t_debug, NULL);
	pthread_join(t_dij, NULL);
	pthread_join(t_router, NULL);
	
	close(clisock);
	close(rousock);
	return 0;
}
