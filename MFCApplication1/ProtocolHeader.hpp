
#ifndef __PROTOCOL_HEADER
#define __PROTOCOL_HEADER

typedef struct ip_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

typedef struct ip_header {
	u_char ver_ihl;				// Version (4 bits) + Internet header length (4 bits)  
	u_char tos;					// Type of service   
	u_short tlen;					// Total length   
	u_short identification;		// Identification  
	u_short flags_fo;			// Flags (3 bits) + Fragment offset (13 bits)  
	u_char ttl;					// Time to live  
	u_char proto;				// Protocol  
	u_short crc;					// Header checksum  
	ip_address saddr;			// Source address  
	ip_address daddr;			// Destination address  
	u_int op_pad;				// Option + Padding  
}ip_header;

typedef struct udp_header {
	u_short sport;		// Source port  
	u_short dport;		// Destination port  
	u_short len;			// Datagram length  
	u_short crc;			// Checksum  
}udp_header;

typedef struct ether_header {
	u_char dst_host[6];
	u_char src_host[6];
	u_short frame_type;
}ether_header;

typedef struct tcp_header {
	u_short sport;		// Source port  
	u_short dport;		// Destination port  
	u_int seqnum;		// Sequence Number  
	u_int acknum;		// Acknowledgement number  
	u_char hlen;			// Header length  
	u_char flags;			// packet flags  
	u_short win;			// Window size  
	u_short crc;			// Header Checksum  
	u_short urgptr;		// Urgent pointer...still don't know what this is...  
}tcp_header;

typedef struct icmp_header {
	u_char type;
	u_char code;
	u_short checksum;
	u_short id;
	u_short seq;
}icmp_header;

typedef struct arp_header {
	u_short htype;		// Hardware Type
	u_short ptype;		// Protocol Type
	u_char hlen;			// Hardware Address Length
	u_char plen;        // Protocol Address Length
	u_short oper;		// Operation Code
	u_char sha[6];      // Sender hardware address
	u_char spa[4];      // Sender IP address
	u_char tha[6];      // Target hardware address
	u_char tpa[4];      // Target IP address
}arp_header;

#endif