struct eth_header{
	uint8_t dest_MAC[6];
	uint8_t src_MAC[6];
	uint16_t type;
} __attribute__((packed));

struct arp_header{
	uint16_t hw_type;
	uint16_t proto;
	uint8_t hw_size;
	uint8_t proto_size;
	uint16_t opcode;
	uint8_t send_MAC[6];
	uint32_t send_ip;
	uint8_t targ_MAC[6];
	uint32_t targ_ip;
} __attribute__((packed));

struct ip_header{
	uint8_t hdr_len : 4;
	uint8_t version : 4;
	uint8_t ecn : 2;
	uint8_t dsc : 6;
	uint16_t tot_len;
	uint16_t id;
	uint16_t flags_frag_offset;
	uint8_t ttl;
	uint8_t proto;
	uint16_t checksum;
	uint32_t src;
	uint32_t dest;
} __attribute__((packed));

struct icmp_header{
	uint8_t type;
} __attribute__((packed));

struct udp_header{
	uint16_t src_port;
	uint16_t dest_port;
} __attribute__((packed));

struct tcp_header{
	uint16_t src_port;
	uint16_t dest_port;
	uint32_t seq;
	uint32_t ack_num;
	uint8_t ns : 1;
	uint8_t reserved : 3;
	uint8_t offset : 4;
	uint8_t fin : 1;
	uint8_t syn : 1;
	uint8_t rst : 1;
	uint8_t psh : 1;
	uint8_t ack : 1;
	uint8_t urg : 1;
	uint8_t ece : 1;
	uint8_t cwr : 1;
	uint16_t window_size;
	uint16_t checksum;
} __attribute__((packed));