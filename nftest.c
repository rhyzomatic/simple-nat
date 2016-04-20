/*
 * nftest.c
 * - demo program of netfilter_queue
 * - Patrick P. C. Lee
 *
 * - To run it, you need to be in root
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "checksum.h"
extern "C" {
#include <linux/netfilter.h>     /* Defines verdicts (NF_ACCEPT, etc) */
#include <libnetfilter_queue/libnetfilter_queue.h>
}

struct natent{
	int src_port;
	struct in_addr src;	
//	int dst_port;
	struct timeval tv;
} table[65536];

#define start_port 10000
#define end_port 12000

void print_table(){
	printf("%15s%10s%15s%10s\n","SRC IP","SRC PORT","DEST IP", "DEST PORT");
	printf("--------------------------------------------------------------------\n");
	int port;
	for (port = start_port; port <= end_port; port++){
		if (table[port].src_port > 0) {
			printf("%15s%10d%15s%10d\n", inet_ntoa(table[port].src),table[port].src_port,"10.0.28.1",port);
		}
	}

}

/*
 * Callback function installed to netfilter queue
 */
static int Callback(nfq_q_handle* myQueue, struct nfgenmsg* msg, 
		nfq_data* pkt, void *cbData) {
	unsigned int id = 0;
	nfqnl_msg_packet_hdr *header;

	printf("pkt recvd: ");
	if ((header = nfq_get_msg_packet_hdr(pkt))) {
		id = ntohl(header->packet_id);
		printf("  id: %u\n", id);
		printf("  hw_protocol: %u\n", ntohs(header->hw_protocol));		
		printf("  hook: %u\n", header->hook);
	}

	// print the timestamp (PC: seems the timestamp is not always set)
	struct timeval tv;
	if (!nfq_get_timestamp(pkt, &tv)) {
		printf("  timestamp: %lu.%lu\n", tv.tv_sec, tv.tv_usec);
	} else {
		printf("  timestamp: nil\n");
	}

	// Print the payload; in copy meta mode, only headers will be
	// included; in copy packet mode, whole packet will be returned.
	printf(" payload: ");
	unsigned char *pktData;
	int len = nfq_get_payload(pkt, (char**)&pktData);
	if (len > 0) {
		for (int i=0; i<len; ++i) {
			printf("%02x ", pktData[i]);
		}
	}
	printf("\n");

	// add a newline at the end
	printf("\n");

	struct ip* ip_hdr = (struct ip*) pktData;
	struct tcphdr * tcp_hdr = (struct tcphdr*) ((unsigned char*)pktData + (ip_hdr->ip_hl << 2));

	printf("src ip=%s\n",inet_ntoa(ip_hdr->ip_src));
	printf("dest ip=%s\n",inet_ntoa(ip_hdr->ip_dst));
	printf("src port=%d\n",ntohs(tcp_hdr->source));
	printf("dst port=%d\n",ntohs(tcp_hdr->dest));
	struct in_addr addr;
	inet_aton("10.0.28.1",&addr);

//	clear_timeout_entry();
print_table();
	u_int32_t verdict = NF_ACCEPT;
	if (ip_hdr->ip_src.s_addr == addr.s_addr) { // INBOUND

		//TODO: SYN, RST packet detection
		//TODO: NAT TABLE
		//TODO: handle timeout
		//TODO: check for first available port
		//TODO: print NAT TABLE
		int port = ntohs(tcp_hdr->dest);
		if (port >= start_port && port <= end_port && table[port].src_port != 0){
			ip_hdr->ip_dst = table[port].src;
			tcp_hdr->dest = table[port].src_port;
		} else { // NOT IN PORT RANGE
			verdict = NF_DROP;
		}
	} else { //OUTBOUND
		if (tcp_hdr->syn == 1){ // IS SYN PACKET
			int port;
			for (port = start_port; port <= end_port; port++){
				if (table[port].src_port == 0) { // valid
					table[port].src = ip_hdr->ip_src;
					table[port].src_port = ntohs(tcp_hdr->source);
					table[port].tv = tv;
					tcp_hdr->source = port;
					break;
				}
			}
		} else { // NOT SYN PACKET

			//TODO: FIN PACKET

			int port;
			for (port = start_port; port <= end_port; port++){
				if (table[port].src.s_addr == ip_hdr->ip_src.s_addr && table[port].src_port == ntohs(tcp_hdr->source)) {
					break;
				}
			}
			if (port > end_port) { // NOT IN TABLE
				verdict = NF_DROP;
			} else { // IN TABLE
				tcp_hdr->source = port;
			}

		}
		ip_hdr->ip_src = addr;

	}


	//tcp_hdr->src_port
	//tcp_hdr->dst_port


	printf("src ip=%s\n",inet_ntoa(ip_hdr->ip_src));

	// fix checksums
	tcp_hdr->check = tcp_checksum((unsigned char *)ip_hdr);
	ip_hdr->ip_sum = ip_checksum((unsigned char *)ip_hdr);

	// For this program we'll always accept the packet...
	return nfq_set_verdict(myQueue, id, verdict, len, (unsigned char *)ip_hdr);

	// end Callback
}

/*
 * Main program
 */
int main(int argc, char **argv) {
	struct nfq_handle *nfqHandle;

	struct nfq_q_handle *myQueue;
	struct nfnl_handle *netlinkHandle;

	int fd, res;
	char buf[4096];

	// Get a queue connection handle from the module
	if (!(nfqHandle = nfq_open())) {
		fprintf(stderr, "Error in nfq_open()\n");
		exit(-1);
	}

	// Unbind the handler from processing any IP packets 
	// (seems to be a must)
	if (nfq_unbind_pf(nfqHandle, AF_INET) < 0) {
		fprintf(stderr, "Error in nfq_unbind_pf()\n");
		exit(1);
	}

	// Bind this handler to process IP packets...
	if (nfq_bind_pf(nfqHandle, AF_INET) < 0) {
		fprintf(stderr, "Error in nfq_bind_pf()\n");
		exit(1);
	}

	// Install a callback on queue 0
	if (!(myQueue = nfq_create_queue(nfqHandle,  0, &Callback, NULL))) {
		fprintf(stderr, "Error in nfq_create_queue()\n");
		exit(1);
	}

	// Turn on packet copy mode
	if (nfq_set_mode(myQueue, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "Could not set packet copy mode\n");
		exit(1);
	}

	netlinkHandle = nfq_nfnlh(nfqHandle);
	fd = nfnl_fd(netlinkHandle);

	while ((res = recv(fd, buf, sizeof(buf), 0)) && res >= 0) {
		// I am not totally sure why a callback mechanism is used
		// rather than just handling it directly here, but that
		// seems to be the convention...
		nfq_handle_packet(nfqHandle, buf, res);
		// end while receiving traffic
	}

	nfq_destroy_queue(myQueue);

	nfq_close(nfqHandle);

	return 0;

	// end main
}

