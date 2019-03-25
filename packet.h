#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#define Mac_LEN 6
#define SIZE_ETHER 14
#define IPTYPE 8
#define TCPTYPE 6
#define IP_HL(ip)  (((ip)->hdr_len) & 0x0f)
#define IP_V(ip) (((ip)->hdr_len) >> 4)
struct ethernet_h{
    uint8_t Dm[Mac_LEN];
    uint8_t Sm[Mac_LEN];
    uint16_t ether_type;
};

struct ip_h{
    uint8_t hdr_len:4;
    uint8_t version:4;
    uint8_t tos;
    uint16_t total_length;
    uint16_t lden;
    uint16_t offset;
    uint8_t time_to_live;
    uint8_t protocol;
    uint16_t checksum;
    uint8_t src_ip[4];
    uint8_t dst_ip[4];

};

struct tcp_h{
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t sequence_number;
    uint32_t acknowledgement_number;
    uint8_t reserved;
    uint8_t window;
    uint8_t cheksum1;
    uint8_t urgent_pointer;


};


struct ethernet_h *ether;
struct ip_h *ih;
struct tcp_h *tcp;

void PrintMac(unsigned char *mac);
void Ip(struct in_addr *ip);
void TCP(uint16_t *tcp);



