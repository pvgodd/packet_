#include <stdio.h>
#include <pcap.h>

#include "packet.h"


void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
    usage();
    return -1;

  u_int size_ip;
  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }


  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    ether = (struct ethernet_h *)(packet);
    ih = (struct ip_h *)(packet + SIZE_ETHER);
    size_ip=IP_HL(ih) * 4;
    tcp = (struct tcp_h *) (packet + SIZE_ETHER + size_ip);


    printf("Ehternet \n");
    printf("Source Mac  :");
    PrintMac(ether -> Sm);
    printf("Destination Mac :");
    PrintMac(ether -> Dm);
    printf("\nIp\n");
    printf("Source Ip   :");
    Ip(ih -> src_ip);
    printf("Destination Ip  ;");
    Ip(ih -> dst_ip);
    printf("TCP");
    printf("Source Port     :");
    TCP(tcp -> src_port);
    printf("Destination Port    :");
    TCP(tcp -> dst_port);
  }

 pcap_close(handle);
 return 0;
}


