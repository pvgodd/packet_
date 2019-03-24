#include "packet.h"

void PrintMac(unsigned char*mac){
    int i;
    for (i = 0; i < Mac_LEN; i++){
        printf("%02x", mac[i]);
        if(i != 5) printf(":");
    }
    printf("\n\n");
}
void Ip(struct in_addr *ip){
    if(ether -> ether_type == IPTYPE){
    char buf[16]={0,};
    inet_ntop(AF_INET, ip, buf, sizeof(buf));
    printf("%s\n",buf);
    }
}
void TCP(uint16_t tcp){
    if(ih -> protocol == TCPTYPE){
    printf("%d\n", ntohs(tcp));
    }
}

