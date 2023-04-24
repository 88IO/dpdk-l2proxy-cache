/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_arp.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#include <signal.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_atomic.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

#define PORT0 0
#define PORT1 1

#define PREFETCH_OFFSET 3

#define CASSANDRA_PORT 9042

#define CACHE_ENTRY_SIZE 8192
#define RESP_MAX_KEY_LENGTH 256
#define CQL_MAX_KEY_LENGTH 256
#define MAX_CACHE_DATA_LENGTH 1024
#define MAX_PREPARED_ID_LENGTH 64
#define PREPARED_ENTRY_SIZE 64

#define KEY_ENTRY_SIZE (512 + CACHE_ENTRY_SIZE)
#define ARP_ENTRY_SIZE 128
#define CONN_ENTRY_SIZE 1024

#define FNV_OFFSET_BASIS_32 2166136261
#define FNV_PRIME_32 16777619

#define IPV4_ADDR_BYTES(ip_addr) (ip_addr & 0xff), \
					((ip_addr >> 8) & 0xff), \
					((ip_addr >> 16) & 0xff), \
					((ip_addr >> 24) & 0xff)

#ifdef DEBUG_BUILD
# define DEBUG_PRINTF(fmt, ...)  printf(fmt, ## __VA_ARGS__);                   
#else
# define DEBUG_PRINTF(fmt, ...)
#endif

#define CQLV4_FLAGS_COMPRESSION 0x01
#define CQLV4_FLAGS_TRACING 0x02
#define CQLV4_FLAGS_CUSTOM_PAYLOAD 0x04
#define CQLV4_FLAGS_WARNING 0x08

enum cql_query_type {
	CQL_QUERY_NULL,
	CQL_QUERY_SELECT,
	CQL_QUERY_UPDATE
};

enum cql_result_kind {
	CQL_RESULT_KIND_VOID          = 0x0001,
	CQL_RESULT_KIND_ROWS          = 0x0002,
	CQL_RESULT_KIND_SET_KEYSPACE  = 0x0003,
	CQL_RESULT_KIND_PREPARED      = 0x0004,
	CQL_RESULT_KIND_SCHEMA_CHANGE = 0x0005
};

enum cql_opecode {
	CQL_OP_ERROR          = 0x00,
	CQL_OP_STARTUP        = 0x01,
	CQL_OP_READY          = 0x02,
	CQL_OP_AUTHENTICATE   = 0x03,
	CQL_OP_OPTIONS        = 0x05,
	CQL_OP_SUPPORTED      = 0x06,
	CQL_OP_QUERY          = 0x07,
	CQL_OP_RESULT         = 0x08,
	CQL_OP_PREPARE        = 0x09,
	CQL_OP_EXECUTE        = 0x0A,
	CQL_OP_REGISTER       = 0x0B,
	CQL_OP_EVENT          = 0x0C,
	CQL_OP_BATCH          = 0x0D,
	CQL_OP_AUTH_CHALLENGE = 0x0E,
	CQL_OP_AUTH_RESPONSE  = 0x0F,
	CQL_OP_AUTH_SUCCESS   = 0x10,
};

static char * const OPECODE[] = {
	[CQL_OP_ERROR]          = "ERROR",
	[CQL_OP_STARTUP]        = "STARTUP",
	[CQL_OP_READY]          = "READY",
	[CQL_OP_AUTHENTICATE]   = "AUTHENTICATE",
	[CQL_OP_OPTIONS]        = "OPTIONS",
	[CQL_OP_SUPPORTED]      = "SUPPORTED",
	[CQL_OP_QUERY]          = "QUERY",
	[CQL_OP_RESULT]         = "RESULT",
	[CQL_OP_PREPARE]        = "RPEPARE",
	[CQL_OP_EXECUTE]        = "EXECUTE",
	[CQL_OP_REGISTER]       = "REGISTER",
	[CQL_OP_EVENT]          = "EVENT",
	[CQL_OP_BATCH]          = "BATCH",
	[CQL_OP_AUTH_CHALLENGE] = "AUTH_CHALLENGE",
	[CQL_OP_AUTH_RESPONSE]  = "AUTH_RESPONSE",
	[CQL_OP_AUTH_SUCCESS]   = "AUTH_SUCCESS",
};

struct tcp_key {
	rte_be32_t client_addr;
	rte_be32_t server_addr;
	rte_be16_t client_port;
};

struct sequence_unique {
	struct tcp_key tcp_key;
	rte_be16_t server_port;
	rte_be32_t seq;
};

struct cache_key {
	uint32_t hash;
	uint32_t len;
	uint32_t pos;
	enum cql_query_type query_type;
	char data[CQL_MAX_KEY_LENGTH];
};

struct cache_entry {
	struct cache_key *key;
	struct rte_mbuf *m_data;
};

struct prepared_entry {
	struct cache_key *key;
	uint32_t id_len;
	char id[MAX_PREPARED_ID_LENGTH];
};

struct tcp_info {
	uint32_t recv_bytes;
	uint32_t send_bytes;
	rte_be32_t _client_seq;
};

struct _stats {
	uint32_t get_hit;
	uint32_t get_miss;
	uint32_t set_hit;
	uint32_t set_miss;
	uint32_t arp;
	uint32_t pass;
	uint32_t reply;
	uint32_t error;
};

struct cqlv4_hdr {
	uint8_t version;
	uint8_t flags;
	rte_be16_t stream;
	uint8_t opecode;
	rte_be32_t length;
} __attribute__((packed));

int skip_whitespace(char *pos) {
	int n = 0;
	while (*pos == ' ') {
		pos++;
		n++;
	};
	return n;
}

int get_cql_token(char *pos) {
	int n = 0;
	if (*pos == '\'') {
		n++;
		do {
			if (unlikely(*pos == '\\')) {
				pos++;
				n++;
			}
			pos++;
			n++;
		} while (*pos != '\'');
	} else if (*pos == ' ' || *pos == ';' || *pos == '=' || *pos == ',') {
		n++;
	} else {
		do {
			if (unlikely(*pos == '\\')) {
				pos++;
				n++;
			}
			pos++;
			n++;
		} while (*pos != ' ' && *pos != ';' && *pos != '=' && *pos != ','); 
	}
	return n;
}

struct cql_query_conf {
	char *keyspace;
	char *table;
	char *keyname;
	char *fieldname;
	char *keydata;
	char *fielddata;
	uint32_t keyspace_length;
	uint32_t table_length;
	uint32_t keyname_length;
	uint32_t fieldname_length;
	uint32_t keydata_length;
	uint32_t fielddata_length;
	enum cql_query_type type;
};

int cql_update_parse(char *pos, struct cql_query_conf *conf) {
	int n;
	char *c;

	n = get_cql_token(pos);
	if (strncmp(pos, "UPDATE", 6))
		return -1;

	pos += n;
	pos += skip_whitespace(pos);

	n = get_cql_token(pos);
	conf->table = pos;
	conf->table_length = n;
	for (int i = 0; i < n; i++) {
		if (*(pos + i) == '.') {
			conf->keyspace = pos;
			conf->keyspace_length = i;
			conf->table = pos + i + 1;
			conf->table_length = n - i - 1;
			break;
		}
	}

	pos += n;
	pos += skip_whitespace(pos);

	n = get_cql_token(pos);
	if (strncmp(pos, "SET", 3)) {
		return -1;
	}

	pos += n;
	pos += skip_whitespace(pos);

	n = get_cql_token(pos);
	conf->fieldname = pos;
	conf->fieldname_length = n;
	
	pos += n;
	pos += skip_whitespace(pos);

	n = get_cql_token(pos);
	if (n != 1 || *pos != '=') {
		return -1;
	}

	pos += n;
	pos += skip_whitespace(pos);

	n = get_cql_token(pos);
	if (n != 1 && n != '?') {
		conf->fielddata = pos;
		conf->fielddata_length = n;
	}

	pos += n;
	pos += skip_whitespace(pos);

	n = get_cql_token(pos);
	if (strncmp(pos, "WHERE", 5)) {
		return -1;
	}

	pos += n;
	pos += skip_whitespace(pos);

	n = get_cql_token(pos);
	conf->keyname = pos;
	conf->keyname_length = n;

	pos += n;
	pos += skip_whitespace(pos);

	n = get_cql_token(pos);
	if (n != 1 || *pos != '=') {
		return -1;
	}

	pos += n;
	pos += skip_whitespace(pos);

	n = get_cql_token(pos);
	if (n != 1 && n != '?') {
		conf->keydata = pos;
		conf->keydata_length = n;
		if (*pos == '\'') {
			conf->keydata += 1;
			conf->keydata_length -= 2;
		}
	}

	pos += n;
	pos += skip_whitespace(pos);

	n = get_cql_token(pos);
	if (n != 1 || *pos != ';') {
		return -1;
	}

	conf->type = CQL_QUERY_UPDATE;
	return 0;
}

int cql_select_parse(char *pos, struct cql_query_conf *conf) {
	int n;
	char *c;
	n = get_cql_token(pos);
	if (strncmp(pos, "SELECT", 6))
		return -1;

	pos += n;
	pos += skip_whitespace(pos);

	n = get_cql_token(pos);
	conf->fieldname = pos;
	conf->fieldname_length = n;

	pos += n;
	pos += skip_whitespace(pos);

	n = get_cql_token(pos);
	if (strncmp(pos, "FROM", 4)) {
		return -1;
	}

	pos += n;
	pos += skip_whitespace(pos);

	n = get_cql_token(pos);
	conf->table = pos;
	conf->table_length = n;
	for (int i = 0; i < n; i++) {
		if (*(pos + i) == '.') {
			conf->keyspace = pos;
			conf->keyspace_length = i;
			conf->table = pos + i + 1;
			conf->table_length = n - i - 1;
			break;
		}
	}
	
	pos += n;
	pos += skip_whitespace(pos);

	n = get_cql_token(pos);
	if (strncmp(pos, "WHERE", 5)) {
		return - 1;
	}

	pos += n;
	pos += skip_whitespace(pos);

	n = get_cql_token(pos);
	conf->keyname = pos;
	conf->keyname_length = n;

	pos += n;
	pos += skip_whitespace(pos);

	n = get_cql_token(pos);
	if (n != 1 || *pos != '=') {
		return -1;
	}

	pos += n;
	pos += skip_whitespace(pos);

	n = get_cql_token(pos);
	if (n != 1 && n != '?') {
		conf->keydata = pos;
		conf->keydata_length = n;
		if (*pos == '\'') {
			conf->keydata += 1;
			conf->keydata_length -= 2;
		}
	}

	pos += n;
	pos += skip_whitespace(pos);

	n = get_cql_token(pos);
	if (n == 1 && *pos == ';') {
		conf->type = CQL_QUERY_SELECT;
		return 0;
	}
	if (strncmp(pos, "LIMIT", 5)) {
		return - 1;
	}

	pos += n;
	pos += skip_whitespace(pos);

	n = get_cql_token(pos);

	pos += n;
	pos += skip_whitespace(pos);

	n = get_cql_token(pos);
	if (n != 1 || *pos != ';') {
		return -1;
	}
	
	conf->type = CQL_QUERY_SELECT;
	return 0;
}

static inline uint32_t
fnv1a_hash(const char *key, uint32_t length, uint32_t initval) 
{
    uint32_t off;
    uint32_t hash = initval;

    for (off = 0; off < length; off++) {
        hash ^= key[off];
        hash *= FNV_PRIME_32;
    }

    return hash;
}

static inline uint32_t
jhash_tcp_key(const void *key, uint32_t _length, uint32_t _initval) 
{
	uint32_t a, b, c;
	const uint32_t *k = (const uint32_t *)key;

	a = k[0] + RTE_JHASH_GOLDEN_RATIO + 14; 
	b = k[1] + RTE_JHASH_GOLDEN_RATIO + 14;
	c = k[2] + RTE_JHASH_GOLDEN_RATIO + 14;

	__rte_jhash_mix(a, b, c);

	a += k[3] & LOWER16b_MASK;

	__rte_jhash_final(a, b, c);

	return c;
}

static struct rte_hash_parameters key_param = {
	.name = "key_table",
	.entries = KEY_ENTRY_SIZE,
	.key_len = sizeof(struct sequence_unique),
	.hash_func = jhash_tcp_key,
	.hash_func_init_val = 0,
	.socket_id = 0,
	.extra_flag = RTE_HASH_EXTRA_FLAGS_NO_FREE_ON_DEL
};

static struct rte_hash_parameters arp_param = {
	.name = "arp_table",
	.entries = ARP_ENTRY_SIZE,
	.key_len = sizeof(uint32_t),
	.hash_func = rte_jhash,
	.hash_func_init_val = 0,
	.socket_id = 0,
};

static struct rte_hash_parameters tcp_param = {
	.name = "tcp_info",
	.entries = CONN_ENTRY_SIZE,
	.key_len = sizeof(struct tcp_key),
	.hash_func = rte_jhash,
	.hash_func_init_val = 0,
	.socket_id = 0,
};

static volatile bool force_quit;

static struct _stats stats0, stats1, stats0_prev, stats1_prev;

struct rte_hash *arp_handle, *key_handle, *tcp_handle;

static struct cache_entry cache_table[CACHE_ENTRY_SIZE] __rte_cache_aligned;
static struct prepared_entry prepared_table[PREPARED_ENTRY_SIZE] __rte_cache_aligned;

static struct rte_ether_addr arp_table[ARP_ENTRY_SIZE] __rte_cache_aligned;
static struct cache_key key_table[CACHE_ENTRY_SIZE + CONN_ENTRY_SIZE] __rte_cache_aligned;
static struct tcp_info tcp_table[CONN_ENTRY_SIZE] __rte_cache_aligned;

static void 
print_stats() {
	printf("stats: client --> server\n  pass = %u (set_miss = %u, set_hit = %u, get_miss = %u), reply = %u, error = %u\n",
			stats0.pass - stats0_prev.pass, stats0.set_miss - stats0_prev.set_miss, 
			stats0.set_hit - stats0_prev.set_hit, stats0.get_miss - stats0_prev.get_miss,
			stats0.reply - stats0_prev.reply, stats0.error - stats0_prev.error);
	printf("stats: client <-- server\n  pass = %u, reply = %u, error = %u\n",
			stats1.pass - stats1_prev.pass, stats1.reply - stats1_prev.reply, stats1.error - stats1_prev.error);
	stats0_prev = stats0;
	stats1_prev = stats1;
}

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */

/* Main functional part of port initialization. 8< */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	const uint16_t rx_rings = 1, tx_rings = 2;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	struct rte_eth_conf port_conf = {
		.txmode = {
			.mq_mode = RTE_ETH_MQ_TX_NONE,
			.offloads =
				RTE_ETH_TX_OFFLOAD_IPV4_CKSUM |
				RTE_ETH_TX_OFFLOAD_TCP_CKSUM
		}
	};
	struct rte_eth_txconf txconf;
	struct rte_eth_rxconf rxconf;
	struct rte_eth_dev_info dev_info;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	retval = rte_eth_dev_info_get(port, &dev_info);
	if (retval != 0) {
		printf("Error during getting device (port %u) info: %s\n",
				port, strerror(-retval));
		return retval;
	}
	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MULTI_SEGS)
		printf("RTE_ETH_TX_OFFLOAD_MULTI_SEGS = %d\n", 
			!!(port_conf.txmode.offloads & RTE_ETH_TX_OFFLOAD_MULTI_SEGS));

	if (!(dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM)
	    || !(dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_TCP_CKSUM)) {
		return -1;
	}

	port_conf.txmode.offloads &= dev_info.tx_offload_capa;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	rxconf = dev_info.default_rxconf;
	rxconf.offloads = port_conf.rxmode.offloads;
	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), &rxconf, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	/* Starting Ethernet port. 8< */
	retval = rte_eth_dev_start(port);
	/* >8 End of starting of ethernet port. */
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct rte_ether_addr addr;
	retval = rte_eth_macaddr_get(port, &addr);
	if (retval != 0)
		return retval;

	printf("Port %u MAC: %2x:%2x:%2x:%2x:%2x:%2x\n",
			port, RTE_ETHER_ADDR_BYTES(&addr));

	/* Enable RX in promiscuous mode for the Ethernet device. */
	// retval = rte_eth_promiscuous_enable(port);
	/* End of setting RX port in promiscuous mode. */
	// if (retval != 0)
	// 	return retval;

	return 0;
}

static inline uint32_t 
csum32_add(uint32_t a, uint32_t b) {
	//printf("32: a = %x, b = %x, ", a, b);
	a += b;
	//printf("a + b = %x\n", a + (a < b));
	return a + (a < b);
}

static inline uint16_t 
csum16_add(uint16_t a, uint16_t b) {
	//printf("16: a = %x, b = %x, ", a, b);
	a += b;
	//printf("a + b = %x\n", a + (a < b));
	return a + (a < b);
}

static inline void
arp_process(struct rte_ether_hdr *eth, struct rte_ether_addr *src_addr) {
	int ret;
	struct rte_arp_hdr *arp;

	arp = (struct rte_arp_hdr *)(eth + 1);

	if ((ret = rte_hash_add_key(arp_handle, &arp->arp_data.arp_sip)) >= 0) {
		DEBUG_PRINTF("%d: arp_table add key(%u.%u.%u.%u), data(%2x:%2x:%2x:%2x:%2x:%2x)\n", 
				rte_lcore_id(), IPV4_ADDR_BYTES(arp->arp_data.arp_sip), RTE_ETHER_ADDR_BYTES(&arp->arp_data.arp_sha));
		rte_ether_addr_copy(&arp->arp_data.arp_sha, &arp_table[ret]);
	}
	
	if (!rte_is_broadcast_ether_addr(&eth->dst_addr)
			&& (ret = rte_hash_lookup(arp_handle, &arp->arp_data.arp_tip)) >= 0) {
		DEBUG_PRINTF("%d: arp_table lookup key(%d.%d.%d.%d)\n", 
			rte_lcore_id(), IPV4_ADDR_BYTES(arp->arp_data.arp_tip));

		rte_ether_addr_copy(&arp_table[ret], &eth->dst_addr);
	}

	rte_ether_addr_copy(src_addr, &arp->arp_data.arp_sha);
}

int update_cache() {

	return 0;
}

int invalidate_cache() {
	return 0;
}

static inline int
client_packet_process(struct rte_mbuf *m, struct rte_ether_addr *eth_tx_port_addr,
					  struct rte_mbuf **buf_pass, struct rte_mbuf **buf_reply) {
	int ret, ret_hit;
	uint32_t lcore_id, sig, cql_body_len;
	struct rte_ether_hdr *eth;
	struct rte_ipv4_hdr *ipv4h;
	struct rte_tcp_hdr *tcph;
	struct cqlv4_hdr *cqlv4h;
	struct sequence_unique seq_uniq = {
		.server_port = CASSANDRA_PORT
	};
	struct tcp_info *hit_info;
	struct cql_query_conf query_conf;
	rte_be32_t *query_length_ptr;
	void *query_ptr, *cql_body;
	enum cql_query_type query_type;

	lcore_id = rte_lcore_id();

	eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

	if (eth->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
		ipv4h = (struct rte_ipv4_hdr *)(eth + 1);

		if (ipv4h->next_proto_id != IPPROTO_TCP)
			goto pass;	

		tcph = (struct rte_tcp_hdr *)((void *)ipv4h + (ipv4h->ihl << 2));

		if (tcph->dst_port != rte_cpu_to_be_16(CASSANDRA_PORT))
			goto pass;

		seq_uniq.tcp_key.client_addr = ipv4h->src_addr;
		seq_uniq.tcp_key.server_addr = ipv4h->dst_addr;
		seq_uniq.tcp_key.client_port = tcph->src_port;	
	
		sig = rte_hash_hash(tcp_handle, &seq_uniq);
		if (tcph->tcp_flags & (RTE_TCP_FIN_FLAG | RTE_TCP_SYN_FLAG)) {
			ret = rte_hash_del_key_with_hash(key_handle, &seq_uniq, sig);
		}
		if ((ret_hit = rte_hash_lookup_with_hash(tcp_handle, &seq_uniq, sig)) >= 0) {
			hit_info = &tcp_table[ret_hit];
		};

		if (rte_be_to_cpu_16(ipv4h->total_length) <= 9 + (ipv4h->ihl << 2) + (tcph->data_off >> 2))
			goto cql;

		cqlv4h = (struct cqlv4_hdr*)((void*)tcph + (tcph->data_off >> 2));

		DEBUG_PRINTF("version = 0x%02x, flags = 0x%02x, stream_id = %u, opecode = 0x%02x(%s), length = %u\n",
			cqlv4h->version, cqlv4h->flags, 
			rte_be_to_cpu_16(cqlv4h->stream), cqlv4h->opecode, OPECODE[cqlv4h->opecode], 
			rte_be_to_cpu_32(cqlv4h->length));

		cql_body = cqlv4h + 1;
		cql_body_len = rte_be_to_cpu_16(ipv4h->total_length) + (void*)ipv4h - cql_body;
		
		if (cqlv4h->version != 0x04 || !(cqlv4h->opecode & (CQL_OP_QUERY | CQL_OP_PREPARE))) 
			goto cql;

		query_length_ptr = (rte_be32_t*)cql_body;
		uint32_t query_length = rte_be_to_cpu_32(*query_length_ptr);

		query_ptr = (char*)(query_length_ptr + 1); 
		query_conf.type = CQL_QUERY_NULL;


		if (cqlv4h->opecode == CQL_OP_EXECUTE) {
			uint16_t id_len = rte_be_to_cpu_16(*(rte_be16_t*)cql_body);
			char *id_ptr = cql_body + sizeof(rte_be16_t); 
			uint32_t prepared_hash = fnv1a_hash(id_ptr, id_len, FNV_OFFSET_BASIS_32);
			uint32_t prepared_index = prepared_hash % PREPARED_ENTRY_SIZE;
			struct prepared_entry *p_entry = &prepared_table[prepared_index];

			// skip id, consistency(2B) + flags(1B)
			rte_be16_t *value_count_ptr = (rte_be16_t*)(id_ptr + id_len + 3);
			uint16_t value_count = rte_be_to_cpu_16(*value_count_ptr);

			if (!p_entry->key || !p_entry->id)
				goto cql;

			if (id_len != p_entry->id_len || strncmp(id_ptr, p_entry->id, id_len)) 
				goto cql;

			query_conf.type = p_entry->key->query_type;

			if (p_entry->key->query_type == CQL_QUERY_SELECT && value_count == 1) {
				DEBUG_PRINTF("%d: EXECUTE SELECT\n", lcore_id);
				rte_be32_t *value_len_ptr = (rte_be32_t*)(value_count_ptr + 1);
				query_conf.keydata_length = rte_be_to_cpu_32(*value_len_ptr);
				query_conf.keydata = (char*)(value_len_ptr + 1);
			} else if (p_entry->key->query_type == CQL_QUERY_UPDATE && value_count == 2) {
				DEBUG_PRINTF("%d: EXECUTE UPDATE\n", lcore_id);
				rte_be32_t *value_len_ptr = (rte_be32_t*)(value_count_ptr + 1);
				uint32_t fielddata_length = rte_be_to_cpu_32(*value_len_ptr);
				char *fielddata = (char*)(value_len_ptr + 1);

				value_len_ptr = (rte_be32_t*)(fielddata + fielddata_length);
				query_conf.keydata_length = rte_be_to_cpu_32(*value_len_ptr);
				query_conf.keydata = (char*)(value_len_ptr + 1);
			}
		} else if (cqlv4h->opecode == CQL_OP_QUERY) {
			if (cql_select_parse(query_ptr, &query_conf) && cql_update_parse(query_ptr, &query_conf)) 
				goto cql;
			DEBUG_PRINTF("%d: EXECUTE HOOK.\n", lcore_id);
			DEBUG_PRINTF("%d: query: %.*s\n", lcore_id, query_length, (char*)query_ptr);
		}

		if (query_conf.type == CQL_QUERY_SELECT) {
			uint32_t key_hash = fnv1a_hash(query_conf.keydata, query_conf.keydata_length, FNV_OFFSET_BASIS_32);
			uint32_t cache_index = key_hash % CACHE_ENTRY_SIZE;
			struct cache_entry *entry = &cache_table[cache_index];

			if (entry->key && key_hash == entry->key->hash
				           && !strncmp(query_conf.keydata, entry->key->data, query_conf.keydata_length)) {
				DEBUG_PRINTF("%d: SELECT HIT HOOK.\n", lcore_id);

				if (unlikely(m->next))
					goto cql;
				m->pkt_len = m->data_len = (void*)(cqlv4h + 1) - (void*)eth;
				
				rte_pktmbuf_refcnt_update(entry->m_data, 1);
				m->next = entry->m_data;
				m->pkt_len += entry->m_data->pkt_len;
				m->nb_segs = entry->m_data->nb_segs + 1;
				DEBUG_PRINTF("%d: m_data->pkt_len = %u\n", lcore_id, entry->m_data->pkt_len);

				if (ret_hit < 0 && (ret_hit = rte_hash_add_key(tcp_handle, &seq_uniq)) >= 0) {
					hit_info = &tcp_table[ret_hit];
					hit_info->recv_bytes = 0;
					hit_info->send_bytes = 0;
				}
				hit_info->recv_bytes += sizeof(struct cqlv4_hdr) + cql_body_len;
				hit_info->send_bytes += sizeof(struct cqlv4_hdr) + entry->m_data->data_len;
;
				RTE_SWAP(eth->src_addr, eth->dst_addr);
				RTE_SWAP(ipv4h->src_addr, ipv4h->dst_addr);
				RTE_SWAP(tcph->src_port, tcph->dst_port);
				ipv4h->total_length = rte_cpu_to_be_16(m->pkt_len - sizeof(struct rte_ether_hdr));
				ipv4h->hdr_checksum = 0;

				u_int32_t new_seq = tcph->recv_ack;
				tcph->recv_ack = rte_cpu_to_be_32(rte_be_to_cpu_32(tcph->sent_seq) + sizeof(struct cqlv4_hdr) + cql_body_len);
				tcph->sent_seq = new_seq;

				uint32_t pseudo_cksum = csum32_add(
					csum32_add(ipv4h->src_addr, ipv4h->dst_addr),
					(ipv4h->next_proto_id << 24) + rte_cpu_to_be_16(rte_be_to_cpu_16(ipv4h->total_length) - (ipv4h->ihl << 2))
				);
				tcph->cksum = csum16_add(pseudo_cksum & 0xFFFF, pseudo_cksum >> 16);

				if (m->pkt_len < 60)  m->pkt_len = 60;

				cqlv4h->version = 0x84;
				cqlv4h->opecode = CQL_OP_RESULT;
				cqlv4h->length = rte_cpu_to_be_32(entry->m_data->pkt_len);

				m->l2_len = sizeof(struct rte_ether_hdr);
				m->l3_len = sizeof(struct rte_ipv4_hdr);
				m->ol_flags |= (RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_TCP_CKSUM);

				stats0.get_hit++;

				*buf_reply = m;
				return 1;
			} else {
				DEBUG_PRINTF("%d: SELECT MISS HOOK.\n", lcore_id);

				seq_uniq.seq = tcph->recv_ack;

				sig = rte_hash_hash(key_handle, &seq_uniq);
				if ((ret = rte_hash_add_key_with_hash(key_handle, &seq_uniq, sig)) >= 0) {
					struct cache_key *ck = &key_table[ret];
					ck->hash = key_hash;
					ck->len = query_conf.keydata_length;
					ck->pos = ret;
					ck->query_type = CQL_QUERY_SELECT;
					rte_memcpy(ck->data, query_conf.keydata, query_conf.keydata_length);

					DEBUG_PRINTF("%d: add key_info:\n", lcore_id);
					DEBUG_PRINTF("      client_addr = %u\n", seq_uniq.tcp_key.client_addr);
					DEBUG_PRINTF("      server_addr = %u\n", seq_uniq.tcp_key.server_addr);
					DEBUG_PRINTF("      seq = %u\n", seq_uniq.seq);
					DEBUG_PRINTF("      client_port = %u\n", seq_uniq.tcp_key.client_port);
				} else {
					printf("ERR: failed to add key.\n");
				}
				stats0.get_miss++;
			}
		} else if (query_conf.type == CQL_QUERY_UPDATE) { 
			DEBUG_PRINTF("%d: UPDATE HOOK.\n", lcore_id);
			uint32_t key_hash = fnv1a_hash(query_conf.keydata, query_conf.keydata_length, FNV_OFFSET_BASIS_32);
			uint32_t cache_index = key_hash % CACHE_ENTRY_SIZE;
			struct cache_entry *entry = &cache_table[cache_index];
			struct cache_entry old_entry;

			if (entry->key && key_hash == entry->key->hash
				           && !strncmp(query_conf.keydata, entry->key->data, query_conf.keydata_length)) {
				old_entry.key = (struct cache_key*)
					rte_atomic64_exchange((uint64_t*)&entry->key, (uint64_t)NULL);
				old_entry.m_data = (struct rte_mbuf*)
					rte_atomic64_exchange((uint64_t*)&entry->m_data, (uint64_t)NULL);
				if (old_entry.key)
					rte_hash_free_key_with_position(key_handle, old_entry.key->pos);
				if (old_entry.m_data)
					rte_pktmbuf_free(old_entry.m_data);

				stats0.set_hit++;
			} else {
				stats0.set_miss++;
			} 
		} else if (cqlv4h->opecode == CQL_OP_PREPARE) {
			if (cql_select_parse(query_ptr, &query_conf) && cql_update_parse(query_ptr, &query_conf)) 
				goto cql;

			DEBUG_PRINTF("%d: query: %.*s\n", lcore_id, query_length, (char*)query_ptr);
			DEBUG_PRINTF("%d: PREPARE HOOK.\n", lcore_id);

			uint32_t key_hash = fnv1a_hash(query_conf.keydata, query_conf.keydata_length, FNV_OFFSET_BASIS_32);

			seq_uniq.seq = tcph->recv_ack;

			sig = rte_hash_hash(key_handle, &seq_uniq);
			if ((ret = rte_hash_add_key_with_hash(key_handle, &seq_uniq, sig)) >= 0) {
				struct cache_key *ck = &key_table[ret];
				ck->hash = key_hash;
				ck->len = query_conf.keydata_length;
				ck->pos = ret;
				ck->query_type = query_conf.type;
				rte_memcpy(ck->data, query_conf.keydata, query_conf.keydata_length);

				DEBUG_PRINTF("%d: add key_info:\n", lcore_id);
				DEBUG_PRINTF("      client_addr = %u\n", seq_uniq.tcp_key.client_addr);
				DEBUG_PRINTF("      server_addr = %u\n", seq_uniq.tcp_key.server_addr);
				DEBUG_PRINTF("      seq = %u\n", seq_uniq.seq);
				DEBUG_PRINTF("      client_port = %u\n", seq_uniq.tcp_key.client_port);
			} else {
				printf("ERR: failed to add key.\n");
			}
		} 

cql:
		if (ret_hit >= 0) {
			uint32_t csum32 = ~tcph->cksum & 0xFFFF;
			csum32 = csum32_add(csum32_add(csum32, ~tcph->sent_seq), ~tcph->recv_ack);
			tcph->sent_seq = rte_cpu_to_be_32(rte_be_to_cpu_32(tcph->sent_seq) - hit_info->recv_bytes);
			tcph->recv_ack = rte_cpu_to_be_32(rte_be_to_cpu_32(tcph->recv_ack) - hit_info->send_bytes);
			csum32 = csum32_add(csum32_add(csum32, tcph->sent_seq), tcph->recv_ack);
			tcph->cksum = ~csum16_add(csum32 & 0xFFFF, csum32 >> 16);
		}

pass:
		if (!rte_is_broadcast_ether_addr(&eth->dst_addr)
				&& (ret = rte_hash_lookup(arp_handle, &ipv4h->dst_addr)) >= 0) {
			rte_ether_addr_copy(&arp_table[ret], &eth->dst_addr);
		}
	} 
	else if (eth->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
		arp_process(eth, eth_tx_port_addr);
	}

	/* replace ethernet source address (client -> port1) */
	rte_ether_addr_copy(eth_tx_port_addr, &eth->src_addr);
	
	*buf_pass = m;
	return 0;
}

static int
client2server(__rte_unused void *arg)
{
	int ret;
	uint16_t j;
	uint32_t lcore_id, nb_pass, nb_reply;
	struct rte_mbuf *bufs[BURST_SIZE], *bufs_reply[BURST_SIZE];
	struct rte_ether_addr eth_tx_port_addr;

	ret = rte_eth_macaddr_get(1, &eth_tx_port_addr);
	if (ret != 0)
		return ret;

	lcore_id = rte_lcore_id();
	printf("lcore %u: client --> server\n", lcore_id);

	while (likely(!force_quit)) {
		/* Get burst of RX packets, from first port of pair. */
		const uint16_t nb_rx = rte_eth_rx_burst(PORT0, 0, bufs, BURST_SIZE);

		if (unlikely(nb_rx == 0))
			continue;

		nb_reply = 0;

		for (j = 0; j < PREFETCH_OFFSET && j < nb_rx; j++) {
			rte_prefetch0(rte_pktmbuf_mtod(
							bufs[j], void *));
		}
		for (j = 0; j < (nb_rx - PREFETCH_OFFSET); j++) {
			rte_prefetch0(rte_pktmbuf_mtod(
							bufs[j + PREFETCH_OFFSET], void *));
			nb_reply += client_packet_process(bufs[j], &eth_tx_port_addr, 
								&bufs[j - nb_reply], &bufs_reply[nb_reply]);
		}
		for (; j < nb_rx; j++) {
			nb_reply += client_packet_process(bufs[j], &eth_tx_port_addr, 
								&bufs[j - nb_reply], &bufs_reply[nb_reply]);
		}

		const uint16_t nb_tx1 = rte_eth_tx_burst(PORT0, 1, bufs_reply, nb_reply);
		if (unlikely(nb_tx1 < nb_reply)) {
			rte_pktmbuf_free_bulk(&bufs_reply[nb_tx1], nb_reply - nb_tx1);
		}

		nb_pass = nb_rx - nb_reply;
		const uint16_t nb_tx0 = rte_eth_tx_burst(PORT1, 0, bufs, nb_pass);
		if (unlikely(nb_tx0 < nb_pass)) {
			rte_pktmbuf_free_bulk(&bufs[nb_tx0], nb_pass - nb_tx0);
		}

		stats0.pass += nb_tx0;
		stats0.reply += nb_tx1;
		stats0.error += nb_rx - nb_tx0 - nb_tx1;
	}

	return 0;
}

static inline void
server_packet_process(struct rte_mbuf **buf, struct rte_ether_addr *eth_tx_port_addr, struct rte_mempool *clone_pool) {
	int ret;
	struct rte_mbuf *m;
	uint32_t lcore_id, sig, cql_body_len; 
	struct rte_ether_hdr *eth;
	struct rte_ipv4_hdr *ipv4h;
	struct rte_tcp_hdr *tcph;
	struct cqlv4_hdr *cqlv4h;
	struct sequence_unique seq_uniq = {
		.server_port = CASSANDRA_PORT
	};
	struct tcp_info *hit_info;
	void *cql_body;

	lcore_id = rte_lcore_id();

	m = *buf;

	eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

	if (eth->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
		ipv4h = (struct rte_ipv4_hdr *)(eth + 1);

		if (ipv4h->next_proto_id != IPPROTO_TCP) 
			goto pass;
		
		tcph = (struct rte_tcp_hdr *)((void *)ipv4h + (ipv4h->ihl << 2));

		if (tcph->src_port != rte_cpu_to_be_16(CASSANDRA_PORT))
			goto pass;				

		seq_uniq.tcp_key.client_addr = ipv4h->dst_addr;
		seq_uniq.tcp_key.server_addr = ipv4h->src_addr;
		seq_uniq.tcp_key.client_port = tcph->dst_port;
		
		if ((ret = rte_hash_lookup(tcp_handle, &seq_uniq)) >= 0) {
			hit_info = &tcp_table[ret];
			uint32_t csum32 = ~tcph->cksum & 0xFFFF;
			csum32 = csum32_add(csum32_add(csum32, ~tcph->sent_seq), ~tcph->recv_ack);
			tcph->sent_seq = rte_cpu_to_be_32(rte_be_to_cpu_32(tcph->sent_seq) + hit_info->send_bytes);
			tcph->recv_ack = rte_cpu_to_be_32(rte_be_to_cpu_32(tcph->recv_ack) + hit_info->recv_bytes);
			csum32 = csum32_add(csum32_add(csum32, tcph->sent_seq), tcph->recv_ack);
			tcph->cksum = ~csum16_add(csum32 & 0xFFFF, csum32 >> 16);
		};

		if (rte_be_to_cpu_16(ipv4h->total_length) <= 9 + (ipv4h->ihl << 2) + (tcph->data_off >> 2))
			goto pass;

		cqlv4h = (struct cqlv4_hdr*)((void*)tcph + (tcph->data_off >> 2));

		cql_body_len = rte_be_to_cpu_16(ipv4h->total_length) + (void*)ipv4h - (void*)(cqlv4h + 1);

		if (cqlv4h->opecode != CQL_OP_RESULT) 
			goto pass;
		
		seq_uniq.seq = tcph->sent_seq;

		// DEBUG_PRINTF("%d: lookup key_info:\n", lcore_id);
		// DEBUG_PRINTF("      client_addr = %u\n", seq_uniq.tcp_key.client_addr);
		// DEBUG_PRINTF("      server_addr = %u\n", seq_uniq.tcp_key.server_addr);
		// DEBUG_PRINTF("      seq = %u\n", seq_uniq.seq);
		// DEBUG_PRINTF("      client_port = %u\n", seq_uniq.tcp_key.client_port);

		sig = rte_hash_hash(key_handle, &seq_uniq);
		if ((ret = rte_hash_lookup_with_hash(key_handle, &seq_uniq, sig)) < 0) {
			goto pass;
		}

		struct cache_key *ck = &key_table[ret];

		cql_body = cqlv4h + 1;

		uint32_t result_kind = rte_be_to_cpu_32(*(rte_be32_t*)cql_body);

		if (result_kind == CQL_RESULT_KIND_PREPARED) {
			struct prepared_entry *p_entry;
			uint16_t id_len, id_hash, prepared_index;
			char *id_ptr;

			id_len = rte_be_to_cpu_16(*(rte_be16_t*)(cql_body + sizeof(uint32_t)));
			id_ptr = cql_body + sizeof(rte_be32_t) + sizeof(rte_be16_t);
			id_hash = fnv1a_hash(id_ptr, id_len, FNV_OFFSET_BASIS_32);

			prepared_index = id_hash % PREPARED_ENTRY_SIZE;
			p_entry = &prepared_table[prepared_index];

			rte_memcpy(p_entry->id, id_ptr, id_len);
			p_entry->id_len = id_len;
			p_entry->key = ck;
		} else {
			struct cache_entry *c_entry, old_c_entry;
			uint32_t cache_index;

			cache_index = ck->hash % CACHE_ENTRY_SIZE;
			c_entry = &cache_table[cache_index];

			if ((*buf = rte_pktmbuf_clone(m, clone_pool)) == NULL)
				printf("%d: failed to clone mbuf\n", lcore_id);

			if (rte_pktmbuf_adj(m, (void*)(cqlv4h + 1) - (void*)eth) == NULL)
				printf("%d: failed to adjust packet.\n", lcore_id);

			m->pkt_len = cql_body_len;

			rte_hash_del_key_with_hash(key_handle, &seq_uniq, sig);

			old_c_entry.key = (struct cache_key*)
				rte_atomic64_exchange((uint64_t*)&c_entry->key, (uint64_t)ck);
			old_c_entry.m_data = (struct rte_mbuf*)
				rte_atomic64_exchange((uint64_t*)&c_entry->m_data, (uint64_t)m);
			if (old_c_entry.key)
				rte_hash_free_key_with_position(key_handle, old_c_entry.key->pos);
			if (old_c_entry.m_data)
				rte_pktmbuf_free(old_c_entry.m_data);

			DEBUG_PRINTF("%d: cache_table updated %u\n", lcore_id, cache_index);
			DEBUG_PRINTF("entry->data_len = %u\n", c_entry->m_data->data_len);
			DEBUG_PRINTF("%d: data = '%.*s'\n", lcore_id, c_entry->m_data->data_len, (char*)c_entry->m_data->buf_addr);
		}

	pass:			
		if (!rte_is_broadcast_ether_addr(&eth->dst_addr)			
				&& (ret = rte_hash_lookup(arp_handle, &ipv4h->dst_addr)) >= 0) {
			rte_ether_addr_copy(&arp_table[ret], &eth->dst_addr);
		}

	} 
	else if (eth->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
		arp_process(eth, eth_tx_port_addr);
	}

	/* replace ethernet source address (client -> port1) */
	rte_ether_addr_copy(eth_tx_port_addr, &eth->src_addr);
}

static int
server2client(void *pool)
{
	struct rte_mempool *clone_pool = pool;
	int ret, ret_hit;
	uint16_t j;
	uint32_t lcore_id, sig, cache_index, payload_len; 
	struct rte_mbuf *bufs[BURST_SIZE], *bufs_clone[BURST_SIZE];
	struct rte_mbuf *m;
	struct rte_ether_hdr *eth;
	struct rte_ether_addr eth_tx_port_addr;
	struct rte_ipv4_hdr *ipv4h;
	struct rte_tcp_hdr *tcph;
	char *payload;
	struct sequence_unique seq_uniq = {
		.server_port = 6379
	};
	struct cache_entry *entry;
	struct tcp_info *hit_info;

	ret = rte_eth_macaddr_get(0, &eth_tx_port_addr);
	if (ret != 0)
		return ret;

	lcore_id = rte_lcore_id();
	printf("lcore %u: server --> client\n", lcore_id);

	while (likely(!force_quit)) {
		/* Get burst of RX packets, from first port of pair. */
		const uint16_t nb_rx = rte_eth_rx_burst(PORT1, 0, bufs, BURST_SIZE);

		if (unlikely(nb_rx == 0))
			continue;

		for (j = 0; j < PREFETCH_OFFSET && j < nb_rx; j++) {
			rte_prefetch0(rte_pktmbuf_mtod(
							bufs[j], void *));
		}
		for (j = 0; j < (nb_rx - PREFETCH_OFFSET); j++) {
			rte_prefetch0(rte_pktmbuf_mtod(
							bufs[j + PREFETCH_OFFSET], void *));
			server_packet_process(&bufs[j], &eth_tx_port_addr, clone_pool);
		}
		for (; j < nb_rx; j++) {
			server_packet_process(&bufs[j], &eth_tx_port_addr, clone_pool);
		}

		/* Send burst of TX packets, to first port of pair. */
		const uint16_t nb_tx0 = rte_eth_tx_burst(PORT0, 0, bufs, nb_rx);
		stats1.pass += nb_tx0;

		/* Free any unsent packets. */
		if (unlikely(nb_tx0 < nb_rx)) {
			rte_pktmbuf_free_bulk(&bufs[nb_tx0], nb_rx - nb_tx0);
		}

		stats1.error += nb_rx - nb_tx0;
	}

	return 0;
}

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("stats: client --> server\n  pass = %u (set_miss = %u, set_hit = %u, get_miss = %u), reply = %u, error = %u\n",
				stats0.pass, stats0.set_miss, 
				stats0.set_hit, stats0.get_miss,
				stats0.reply, stats0.error);
		printf("stats: client <-- server\n  pass = %u, reply = %u, error = %u\n",
				stats1.pass, stats1.reply, stats1.error);
		force_quit = true;
	}
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool, *clone_pool;
	unsigned nb_ports;
	uint16_t portid;
	int lcoreid;

	/* Initializion the Environment Abstraction Layer (EAL). 8< */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	/* >8 End of initialization the Environment Abstraction Layer (EAL). */

	argc -= ret;
	argv += ret;

	/* add */
	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* add */
	if (rte_lcore_count() < 2)
		rte_exit(EXIT_FAILURE, "Error: number of core must be at least 2\n");

	/* Check that there is an even number of ports to send/receive on. */
	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports < 2)
		rte_exit(EXIT_FAILURE, "Error: number of ports must be at least 2\n");

	/* Creates a new mempool in memory to hold the mbufs. */

	/* Allocates mempool to hold the mbufs. 8< */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	clone_pool = rte_pktmbuf_pool_create("CLONE_POOL", TX_RING_SIZE + BURST_SIZE, BURST_SIZE, 0, 0, rte_socket_id());
	/* >8 End of allocating mempool to hold mbuf. */

	if (mbuf_pool == NULL || clone_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initializing all ports. 8< */
	RTE_ETH_FOREACH_DEV(portid) {
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",
					portid);
	}
	/* >8 End of initializing all ports. */

	if (nb_ports > 2) 
		printf("\nWARNING: Too many ports enabled. Only 2 used.\n");
	if (rte_lcore_count() > 2) 
		printf("\nWARNING: Too many lcores enabled. Only 2 used.\n");

	/* initializeing arp table */
	arp_handle = rte_hash_create(&arp_param);
	if (!arp_handle)
		rte_exit(EXIT_FAILURE, "Cannot init arp table.\n");

	key_handle = rte_hash_create(&key_param);
	if (!key_handle)
		rte_exit(EXIT_FAILURE, "Cannot init key table.\n");

	tcp_handle = rte_hash_create(&tcp_param);
	if (!tcp_handle)
		rte_exit(EXIT_FAILURE, "Cannot init conn table.\n");
	
	//resp_cache = calloc(CACHE_ENTRY_SIZE, sizeof(struct cache_entry));

	rte_eal_remote_launch(server2client, clone_pool, rte_get_next_lcore(-1, 1, 0));

	/* Call lcore_main on the main core only. Called on single lcore. 8< */
	client2server(NULL);
	/* >8 End of called on single lcore. */

	rte_eal_mp_wait_lcore();

	/* clean up the EAL */
	rte_eal_cleanup();

	return 0;
}
