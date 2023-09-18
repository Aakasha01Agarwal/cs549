// #include <pcap.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <math.h>
#define MAX_PKT_LEN 1700
/* TCP header */
    struct sniff_tcp {
        unsigned short th_sport;   /* source port */
        unsigned short th_dport;   /* destination port */
        // tcp_seq th_seq;     /* sequence number */
        // tcp_seq th_ack;     /* acknowledgement number */

        unsigned char th_offx2;    /* data offset, rsvd */
    #define TH_OFF(th)  (((th)->th_offx2 & 0xf0) >> 4)
        unsigned char th_flags;
    #define TH_FIN 0x01
    #define TH_SYN 0x02
    #define TH_RST 0x04
    #define TH_PUSH 0x08
    #define TH_ACK 0x10
    #define TH_URG 0x20
    #define TH_ECE 0x40
    #define TH_CWR 0x80
    #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        unsigned short th_win;     /* window */
        unsigned short th_sum;     /* checksum */
        unsigned short th_urp;     /* urgent pointer */
};
    
void main(){
    FILE *fd;
    char *in_filename = "G:/Wireless Communication/cs549/project1/ipChanged.pcap";
    unsigned int file_header[6], pkt_header[4], captured_len;
    unsigned char one_pkt[MAX_PKT_LEN];

	fd = fopen(in_filename, "rb");

    while (!feof(fd)) {
        printf("hi this is aakash");
        break;
    }

}

