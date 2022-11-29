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

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

#define ARP_ENTRY_SIZE 64

#define IPV4_ADDR_BYTES(ip_addr) (ip_addr && 0xff), \
					((ip_addr >> 8) && 0xff), \
					((ip_addr >> 16) && 0xff), \
					((ip_addr >> 24) && 0xff)

static volatile bool force_quit;

static struct rte_hash_parameters arp_hash = {
	.name = "arp_table",
	.entries = ARP_ENTRY_SIZE,
	.key_len = sizeof(uint32_t),
	.hash_func = rte_jhash,
	.hash_func_init_val = 0,
	.socket_id = 0,
};

static struct rte_ether_addr arp_table[ARP_ENTRY_SIZE];

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */

/* Main functional part of port initialization. 8< */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf;
	const uint16_t rx_rings = 1, tx_rings = 1;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	memset(&port_conf, 0, sizeof(struct rte_eth_conf));

	retval = rte_eth_dev_info_get(port, &dev_info);
	if (retval != 0) {
		printf("Error during getting device (port %u) info: %s\n",
				port, strerror(-retval));
		return retval;
	}

	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
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

	printf("Port %u MAC: %02" PRIx8 ":%02" PRIx8 ":%02" PRIx8
			   ":%02" PRIx8 ":%02" PRIx8 ":%02"PRIx8 "\n",
			port, RTE_ETHER_ADDR_BYTES(&addr));

	// /* Enable RX in promiscuous mode for the Ethernet device. */
	// retval = rte_eth_promiscuous_enable(port);
	// /* End of setting RX port in promiscuous mode. */
	// if (retval != 0)
	// 	return retval;

	return 0;
}
/* >8 End of main functional part of port initialization. */


static inline void
arp_process(struct rte_ether_hdr *eth, struct rte_hash *arp_handle) {
	int ret;
	struct rte_arp_hdr *arp;
	char addr[RTE_ETHER_ADDR_FMT_SIZE];

	arp = (struct rte_arp_hdr *)(eth + 1);
	
	rte_ether_format_addr(addr, RTE_ETHER_ADDR_FMT_SIZE, &arp->arp_data.arp_sha);
	printf("client --> server: add key(%d.%d.%d.%d), data(%s)\n", 
		IPV4_ADDR_BYTES(arp->arp_data.arp_sip), addr);

	if ((ret = rte_hash_add_key(arp_handle, &arp->arp_data.arp_sip)) >= 0)
		rte_ether_addr_copy(&arp->arp_data.arp_sha, &arp_table[ret]);

	if (!rte_is_broadcast_ether_addr(&eth->dst_addr)
			&& (ret = rte_hash_lookup(arp_handle, &arp->arp_data.arp_tip)) >= 0) {
		printf("client --> server: lookup %d.%d.%d.%d\n", 
			IPV4_ADDR_BYTES(arp->arp_data.arp_tip));

		rte_ether_addr_copy(&arp_table[ret], &eth->dst_addr);
	}

	rte_ether_addr_copy(&eth->src_addr, &arp->arp_data.arp_sha);
}

static int
client2server(__rte_unused void *arg)
{
	int ret;
	unsigned lcore_id, j;
	struct rte_mbuf *bufs[BURST_SIZE];
	struct rte_mbuf *m;
	struct rte_ether_hdr *eth;
	struct rte_ether_addr eth_tx_port_addr;
	struct rte_ipv4_hdr *ipv4h;
	struct rte_arp_hdr *arp;
	struct rte_hash *arp_handle;
	char addr[RTE_ETHER_ADDR_FMT_SIZE];
	
	ret = rte_eth_macaddr_get(1, &eth_tx_port_addr);
	if (ret != 0)
		return ret;
	
	arp_handle = rte_hash_find_existing(arp_hash.name);
	if (!arp_handle)
		return -ENOENT;

	lcore_id = rte_lcore_id();
	printf("core %u: client --> server\n", lcore_id);

	while (likely(!force_quit)) {

		/* Get burst of RX packets, from first port of pair. */
		struct rte_mbuf *bufs[BURST_SIZE];
		const uint16_t nb_rx = rte_eth_rx_burst(0, 0,
				bufs, BURST_SIZE);

		if (unlikely(nb_rx == 0))
			continue;

		printf("client --(%u pkts)-> server\n", nb_rx);

		for (j = 0; j < nb_rx; j++) {
			m = bufs[j];
			rte_prefetch0(rte_pktmbuf_mtod(m, void *));

			eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

			rte_ether_addr_copy(&eth_tx_port_addr, &eth->src_addr);

			if (eth->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
				ipv4h = (struct rte_ipv4_hdr *)(eth + 1);

				if (!rte_is_broadcast_ether_addr(&eth->dst_addr)
					 && (ret = rte_hash_lookup(arp_handle, &ipv4h->dst_addr)) >= 0) {
					rte_ether_addr_copy(&arp_table[ret], &eth->dst_addr);
				}

			} else if (eth->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
				arp_process(eth, arp_handle);
			}
		}

		/* Send burst of TX packets, to second port of pair. */
		const uint16_t nb_tx = rte_eth_tx_burst(1, 0, bufs, nb_rx);

		/* Free any unsent packets. */
		if (unlikely(nb_tx < nb_rx)) {
			uint16_t buf;
			for (buf = nb_tx; buf < nb_rx; buf++)
				rte_pktmbuf_free(bufs[buf]);
		}
	}

	return 0;
}

static int
server2client(__rte_unused void *arg)
{
	int ret;
	unsigned lcore_id, j;
	struct rte_mbuf *bufs[BURST_SIZE];
	struct rte_mbuf *m;
	struct rte_ether_hdr *eth;
	struct rte_ether_addr eth_tx_port_addr;
	struct rte_ipv4_hdr *ipv4h;
	struct rte_arp_hdr *arp; 
	struct rte_hash *arp_handle;
	char addr[RTE_ETHER_ADDR_FMT_SIZE];

	// ret = rte_ether_unformat_addr("a0:36:9f:53:ae:c8", &eth_client_addr);
	// if (ret != 0)
	// 	return ret;

	ret = rte_eth_macaddr_get(0, &eth_tx_port_addr);
	if (ret != 0)
		return ret;

	arp_handle = rte_hash_find_existing(arp_hash.name);
	if (!arp_handle)
		return -ENOENT;

	lcore_id = rte_lcore_id();
	printf("core %u: server --> client\n", lcore_id);

	while (likely(!force_quit)) {
		/* Get burst of RX packets, from first port of pair. */
		const uint16_t nb_rx = rte_eth_rx_burst(1, 0,
				bufs, BURST_SIZE);

		if (unlikely(nb_rx == 0))
			continue;

		printf("client <-(%u pkts)-- server\n", nb_rx);

		for (j = 0; j < nb_rx; j++) {
			m = bufs[j];
			rte_prefetch0(rte_pktmbuf_mtod(m, void *));

			eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

			/* replace ethernet source address (client -> port1) */
			rte_ether_addr_copy(&eth_tx_port_addr, &eth->src_addr);

			if (eth->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
				ipv4h = (struct rte_ipv4_hdr *)(eth + 1);

				if (!rte_is_broadcast_ether_addr(&eth->dst_addr)
					 && (ret = rte_hash_lookup(arp_handle, &ipv4h->dst_addr)) >= 0) {
					rte_ether_addr_copy(&arp_table[ret], &eth->dst_addr);
				}

			} else if (eth->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
				arp_process(eth, arp_handle);
			}
		}

		/* Send burst of TX packets, to second port of pair. */
		const uint16_t nb_tx = rte_eth_tx_burst(0, 0, bufs, nb_rx);

		/* Free any unsent packets. */
		if (unlikely(nb_tx < nb_rx)) {
			uint16_t buf;
			for (buf = nb_tx; buf < nb_rx; buf++)
				rte_pktmbuf_free(bufs[buf]);
		}
	}

	return 0;
}

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n",
				signum);
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
	struct rte_mempool *mbuf_pool;
	unsigned nb_ports;
	uint16_t portid;
	struct rte_hash *handle;

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
	/* >8 End of allocating mempool to hold mbuf. */

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initializing all ports. 8< */
	RTE_ETH_FOREACH_DEV(portid)
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",
					portid);
	/* >8 End of initializing all ports. */

	if (nb_ports > 2) 
		printf("\nWARNING: Too many ports enabled. Only 2 used.\n");
	if (rte_lcore_count() > 2) 
		printf("\nWARNING: Too many lcores enabled. Only 2 used.\n");

	/* initializeing arp table */
	handle = rte_hash_create(&arp_hash);
	if (!handle)
		rte_exit(EXIT_FAILURE, "Cannot init arp table.\n");

	// worker lcore
	rte_eal_remote_launch(server2client, NULL, rte_get_next_lcore(-1, 1, 0));

	/* Call lcore_main on the main core only. Called on single lcore. 8< */
	client2server(NULL);
	/* >8 End of called on single lcore. */

	rte_eal_mp_wait_lcore();

	/* clean up arp table */
	rte_hash_free(handle);

	/* clean up the EAL */
	rte_eal_cleanup();

	return 0;
}
