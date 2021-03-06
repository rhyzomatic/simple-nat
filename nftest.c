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
#include <sys/time.h>

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
	double ts;
	int ext_fin_state;
	int ext_fin_seq;
	int cli_fin_state;
	int cli_fin_seq;
} table[65536];

struct in_addr pub_ip, int_ip;
struct in_addr lan;
int mask;
char pub_ip_str[20];

#define start_port 10000
#define end_port 12000

uint16_t ip_checksum(void* vdata,size_t length) {
	// Cast the data pointer to one that can be indexed.
	char* data=(char*)vdata;

	// Initialise the accumulator.
	uint32_t acc=0xffff;

	// Handle complete 16-bit blocks.
	for (size_t i=0;i+1<length;i+=2) {
		uint16_t word;
		memcpy(&word,data+i,2);
		acc+=ntohs(word);
		if (acc>0xffff) {
			acc-=0xffff;
		}
	}

	// Handle any partial block at the end of the data.
	if (length&1) {
		uint16_t word=0;
		memcpy(&word,data+length-1,1);
		acc+=ntohs(word);
		if (acc>0xffff) {
			acc-=0xffff;
		}
	}

	// Return the checksum in network byte order.
	return htons(~acc);
}


void clear_timeout_entries(){
	struct timeval now;
	gettimeofday(&now, NULL);
	double now_ts = now.tv_sec + (double) now.tv_usec / 1000000;

	int entry;
	for (entry = start_port; entry <= end_port; entry++){
		if (table[entry].src_port > 0){
			if (now_ts - table[entry].ts > 30){
				// delete entry
				printf("deleting entry\n");
				memset(&table[entry], 0, sizeof(struct natent));
			}
		}
	}
}

void print_table(){
	printf("%15s%15s%15s%15s%32s\n","SRC IP","SRC PORT","DEST IP", "DEST PORT","TIMEOUT");
	printf("--------------------------------------------------------------------------------------------\n");
	int port;
	for (port = start_port; port <= end_port; port++){
		if (table[port].src_port > 0) {
			printf("%15s%15d%15s%15d%25f\n", inet_ntoa(table[port].src),table[port].src_port,pub_ip_str,port,table[port].ts);
		}
	}
	printf("\n\n");

}

void remove_entry(int port){
	memset(&table[port], 0, sizeof(struct natent));
}


/*
 * Callback function installed to netfilter queue
 */
static int Callback(nfq_q_handle* myQueue, struct nfgenmsg* msg, 
		nfq_data* pkt, void *cbData) {
	printf("=====================================================================================================\n");
	printf("=====================================================================================================\n");
	printf("=====================================================================================================\n");
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
	/*if (!nfq_get_timestamp(pkt, &tv)) {
	//		printf("  timestamp: %lu.%lu\n", tv.tv_sec, tv.tv_usec);
	} else {
	printf("  timestamp: nil\n");
	}*/
	gettimeofday(&tv, NULL);
	printf("creating timeval at %ld seconds\n", tv.tv_sec);
	double ts = tv.tv_sec + (double) tv.tv_usec / 1000000;

	// Print the payload; in copy meta mode, only headers will be
	// included; in copy packet mode, whole packet will be returned.
	//	printf(" payload: ");
	unsigned char *pktData;
	int len = nfq_get_payload(pkt, (char**)&pktData);
	/*	if (len > 0) {
		for (int i=0; i<len; ++i) {
		printf("%02x ", pktData[i]);
		}
		}
		printf("\n");

	// add a newline at the end
	printf("\n");*/

	struct ip* ip_hdr = (struct ip*) pktData;
	struct tcphdr * tcp_hdr = (struct tcphdr*) ((unsigned char*)pktData + (ip_hdr->ip_hl << 2));

	puts("   BEFORE TRANSLATION---");
	printf("   src=%s:%d\n",inet_ntoa(ip_hdr->ip_src),ntohs(tcp_hdr->source));
	printf("   dest=%s:%d\n",inet_ntoa(ip_hdr->ip_dst),ntohs(tcp_hdr->dest));

//	struct in_addr addr;

	//clear timed out entries
	clear_timeout_entries();


//	inet_aton("10.3.1.28",&addr);//TODO:HACK
	unsigned int local_mask = 0xffffffff << (32 - mask);
	u_int32_t verdict = NF_ACCEPT;
	//if (ip_hdr->ip_dst.s_addr == addr.s_addr) { // INBOUND
	if ((ntohl(ip_hdr->ip_src.s_addr) & local_mask) != ntohl(lan.s_addr)){ // INBOUND
		puts("INBOUND");
//		inet_aton("10.0.28.1",&addr);

		//TODO: 4-way handshake
		//TODO: RST packet detection
		//TODO: handle timeout
		int port = ntohs(tcp_hdr->dest);
		if (port >= start_port && port <= end_port && table[port].src_port != 0){
			table[port].ts = ts; // UPDATE TIMESTAMP
			ip_hdr->ip_dst = table[port].src;
			tcp_hdr->dest = htons(table[port].src_port);
			if (tcp_hdr->rst == 1){
				puts("RST!");
				remove_entry(port);
			}
			else{
				if (tcp_hdr->fin == 1){ //INBOUND FIN
					puts("INBOUND FIN");
					table[port].ext_fin_state = 1;
					table[port].ext_fin_seq = ntohs(tcp_hdr->seq);
				}
				
				printf("ACK=%d, cli_fin_seq=%d\n", ntohs(tcp_hdr->ack_seq), table[port].cli_fin_seq);

				if ((table[port].cli_fin_state == 1) && (ntohs(tcp_hdr->ack_seq) == table[port].cli_fin_seq)){
					puts("EXT HAS ACK'ed CLIENT FIN");
					table[port].cli_fin_state = 2; //ext has ack'ed client fin

					if ((table[port].cli_fin_state == 2) && (table[port].ext_fin_state == 2)){
						//FIN SEQUENCE COMPLETE, CAN DROP ENTRY
						puts("DROPPING ENTRY B/C CLI AND EXT ACK'ed FINS");
						remove_entry(port);
					}
				}

			}

		} else { // NOT IN PORT RANGE
			puts("NOT IN PORT RANGE");
			verdict = NF_DROP;
		}
	} else { //OUTBOUND
//		inet_aton("10.3.1.28",&addr);
		puts("OUTBOUND");
		int p;
		for (p = start_port; p <= end_port; p++){
			if (table[p].src.s_addr == ip_hdr->ip_src.s_addr && table[p].src_port == ntohs(tcp_hdr->source)) {
				break;
			}
		}

		if (p <= end_port){ // EXIST PAIR
			tcp_hdr->source = htons(p);
			table[p].ts = ts; // UPDATE TIMESTAMP
			if (tcp_hdr->rst == 1){
				puts("RST!");
				remove_entry(p);
			}
			else {
				if (tcp_hdr->fin == 1){ //OUTBOUND FIN
					puts("OUTBOUND FIN");
					table[p].cli_fin_state = 1;
					table[p].cli_fin_seq = ntohs(tcp_hdr->seq);
				}

				if ((table[p].ext_fin_state == 1) && (ntohs(tcp_hdr->ack_seq) == table[p].ext_fin_seq)){
					puts("CLIENT ACK'ed EXT FIN");
					table[p].ext_fin_state = 2; //client has ack'ed ext fin

					if ((table[p].ext_fin_state == 2) && (table[p].cli_fin_state == 2)){
						//FIN SEQUENCE COMPLETE, CAN DROP ENTRY
						puts("DROPPING ENTRY B/C CLI AND EXT ACK'ed FINS");
						remove_entry(p);
					}
				}
			}

		}else if (tcp_hdr->syn == 1){ // NO PAIR AND IS SYN
			puts("SYN");
			int port;
			for (port = start_port; port <= end_port; port++){
				if (table[port].src_port == 0) { // valid
					table[port].src = ip_hdr->ip_src;
					table[port].src_port = ntohs(tcp_hdr->source);
					table[port].ts = ts; // UPDATE TIMESTAMP
					tcp_hdr->source = htons(port);
					break;
				}
			}
		}else{ // NO PAIR AND NO SYN
			verdict = NF_DROP;

		}
		ip_hdr->ip_src = pub_ip;

	}

	print_table();

	// fix checksums
	ip_hdr->ip_sum = ip_checksum((unsigned char *)ip_hdr);
	//ip_hdr->ip_sum = ip_checksum((unsigned char *)ip_hdr,20);
	tcp_hdr->check = tcp_checksum((unsigned char *)ip_hdr);
	puts("   AFTER---");
	printf("   src=%s:%d\n",inet_ntoa(ip_hdr->ip_src),ntohs(tcp_hdr->source));
	printf("   dest=%s:%d\n",inet_ntoa(ip_hdr->ip_dst),ntohs(tcp_hdr->dest));

	// For this program we'll always accept the packet...
	return nfq_set_verdict(myQueue, id, verdict, len, (unsigned char *)ip_hdr);

	// end Callback
}

/*
 * Main program
 */
int main(int argc, char **argv) {
	if (argc!=4) {
		printf("Usage: %s <public ip> <internal ip> <subnet mask>\n",argv[0]);
		return 0;
	}

	puts("hi...");

	inet_aton(argv[1],&pub_ip);
	strcpy(pub_ip_str,inet_ntoa(pub_ip));
	inet_aton(argv[2],&int_ip);
	mask = atoi(argv[3]);
	unsigned int local_mask = 0xffffffff << (32 - mask);
	lan.s_addr = htonl(ntohl(int_ip.s_addr) & local_mask);

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

