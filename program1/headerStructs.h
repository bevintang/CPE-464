struct eth_header{
	uint8_t dest_MAC[6];
	uint8_t src_MAC[6];
	uint16_t type;
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