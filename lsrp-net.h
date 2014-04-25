#ifndef __LSRP_NET_H__
#define __LSRP_NET_H__

int udp_snd(char *ip, int port, void *buf, unsigned long len)
{
	struct sockaddr_in si_other;
	int sock, slen = sizeof(struct sockaddr_in);
	
	if((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
	{
		perror("failed to create socket");
		close(sock);
		return errno;
	}
	
	bzero((char *) &si_other, slen);
	si_other.sin_family = AF_INET;
    si_other.sin_port = htons(port);
    if(inet_aton(ip, &si_other.sin_addr) == 0)
    {
		fprintf(stderr, "invalid ip addresss");
		close(sock);
		return -EINVAL;
	}
	
	int ret = sendto(sock, buf, len, 0, (struct sockaddr *)&si_other, slen);
	close(sock);
	
	return ret;	
}

int udp_rcv(int port, void *buf, unsigned long len, struct sockaddr *si_other)
{
	struct sockaddr_in si_me;
	int sock, slen = sizeof(struct sockaddr_in);
	
	if((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
	{
		perror("failed to create socket");
		close(sock);
		return errno;
	}
	
	bzero((char *) &si_me, slen);
	si_me.sin_family = AF_INET;
    si_me.sin_port = htons(port);
    si_me.sin_addr.s_addr = htonl(INADDR_ANY);
    if(bind(sock, (struct sockaddr *)&si_me, slen) < 0)
    {
		perror("failed to bind socket");
		close(sock);
		return errno;
	}
    
    int ret = recvfrom(sock, buf, len, 0, si_other, &slen);
    close(sock);
    
    return ret;
}

int udp_rcv_nobind(int sock, void *buf, unsigned long len, struct sockaddr *si_other)
{
	struct sockaddr_in si_me;
	int slen = sizeof(struct sockaddr_in);
	    
    int ret = recvfrom(sock, buf, len, 0, si_other, &slen);
    return ret;
}

int udp_sock_bind(int port)
{
	struct sockaddr_in si_me;
	int sock, slen = sizeof(struct sockaddr_in);
	
	if((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
	{
		perror("failed to create socket");
		return errno;
	}
	
	bzero((char *) &si_me, slen);
	si_me.sin_family = AF_INET;
	si_me.sin_port = htons(port);
	si_me.sin_addr.s_addr = htonl(INADDR_ANY);
	if(bind(sock, (struct sockaddr *)&si_me, slen) < 0)
	{
		perror("failed to bind socket");
		return errno;
	}
	
	return sock;
}

#endif
