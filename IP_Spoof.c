// IP Spoofer - Ryoon Ivo <ryoonivo@gmail.com>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <linux/tcp.h>
#include <linux/ip.h>


#define DEFAULT_TTL 255
#define IPVERSION 4
#define TH_OFFSET 5
#define TCP_WINDOW_SIZE 512

// To calculate the TCP checksum
struct pseudohdr{
	struct in_addr source_address;
	struct in_addr dest_address;
	unsigned char place_holder;
	unsigned char protocol;
	unsigned short length;
} pseudohdr;

// Checksum counting function
unsigned short in_cksum(unsigned short *addr, int len);


int main(int argc, char *argv[]){
	unsigned char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
	struct sockaddr_in sock;
	struct tcphdr *tcp;
	struct iphdr *iphdr;
	char *pseudo_packet;
	unsigned short sport, dport;
	struct in_addr saddr, daddr;
	unsigned long seq, ack;
	int s, on = 1;

	if(argc < 5){
		printf("usage: %s <source address> <source port> <destination address> <destination port>\n", argv[0]);
		exit(1);
	};
	// Source address argument
	saddr.s_addr = inet_addr(argv[1]);
	// Source port argument
	sport = (unsigned short)atoi(argv[2]);
	// Destination address argument
	daddr.s_addr = inet_addr(argv[3]);
	// Destination port argument
	dport = (unsigned short)atoi(argv[4]);

	if((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0){
		perror("socket");
		exit(1);
	};

	if(setsockopt(s, IPPROTO_IP, IP_HDRINCL, (char *)&on, sizeof(on)) < 0){
		perror("setsockopt");
		exit(1);
	};

	seq = rand() % time(NULL);
	ack = rand() % time(NULL);

	// Fill in the required IP header fields
	iphdr = (struct iphdr *)packet;
	memset((char *)iphdr, '\0', sizeof(struct iphdr));
	// 4-bit Version
	iphdr->version = IPVERSION;
	// 4-bit header length in 32 bit words
	iphdr->ihl = 5;
	// 16-bit total length of the entire segment
	iphdr->tot_len = htons(sizeof(packet));
	// 16-bit Segment unique identifier
	iphdr->id = htons(getpid());
	// 8-bit package lifetime
	iphdr->ttl = DEFAULT_TTL;
	// 8-bit Top Level Protocol
	iphdr->protocol = IPPROTO_TCP;
	// 16-bit Checksum
	iphdr->check = (unsigned short)in_cksum((unsigned short *)iphdr, sizeof(struct iphdr));
	// 32-bit sender address
	iphdr->saddr = saddr.s_addr;
	// 32-bit Recipient Address
	iphdr->daddr = daddr.s_addr;

	// Fill in the TCP header fields we need
	tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));
	memset((char *)tcp, '\0', sizeof(struct tcphdr));
	// 16-bit port of the sender
	tcp->source = htons(sport);
	// 16-bit port of the recipient
	tcp->dest = htons(dport);
	// 32-bit unique sequence number
	tcp->seq = htonl(seq);
	// 32-bit Verification Number
	tcp->ack_seq = htonl(ack);
	// Offset data in a TCP packet in 32 bit words
	tcp->doff = TH_OFFSET;
	// Connection setting flag
	tcp->syn = 1;
	// 16-bit window size
	tcp->window = htons(TCP_WINDOW_SIZE);

	// Filling in a pseudo header to calculate the checksum of a TCP packet (read the TCP/IP specification)
	pseudohdr.protocol = IPPROTO_TCP;
	pseudohdr.length = htons(sizeof(struct tcphdr));
	pseudohdr.place_holder = 0;
	pseudohdr.source_address = saddr;
	pseudohdr.dest_address = daddr;

	if((pseudo_packet = (char *)malloc(sizeof(pseudohdr) + sizeof(struct tcphdr))) == NULL){
		perror("malloc");
		exit(1);
	};

	memcpy(pseudo_packet, &pseudohdr, sizeof(pseudohdr));
	memcpy((pseudo_packet + sizeof(pseudohdr)), tcp, sizeof(struct tcphdr));
	tcp->check = (unsigned short)in_cksum((unsigned short *)pseudo_packet, (sizeof(struct tcphdr) + sizeof(pseudohdr)));
	free(pseudo_packet);

	memset(&sock, '\0', sizeof(sock));
	sock.sin_family = AF_INET;
	sock.sin_port   = htons(dport);
	sock.sin_addr   = daddr;

	if(sendto(s, &packet, sizeof(packet), 0x0, (struct sockaddr *)&sock, sizeof(sock)) != sizeof(packet)){
		perror("sendto");
		exit(1);
	};

	exit(0);
}

// This is a standard function to calculate the checksum  
unsigned short in_cksum(unsigned short *addr,int len){
	register int sum = 0;
    u_short answer = 0;
    register u_short *w = addr;
    register int nleft = len;

    // Using a 32 bit accumulator (sum), we add
    // sequential 16 bit words to it, and at the end, fold back all the
    // carry bits from the top 16 bits into the lower 16 bits.
    
    while (nleft > 1){
		sum += *w++;
		nleft -= 2;
    }

	/* mop up an odd byte, if necessary */
	if (nleft == 1){
		*(u_char *)(&answer) = *(u_char *)w ;
		sum += answer;
    }

	/* add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
	sum += (sum >> 16);                     /* add carry */
	answer = ~sum;                          /* truncate to 16 bits */
	return(answer);
}
