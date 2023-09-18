#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <math.h>

#define TCP_TYPE_NUM 6
#define LEFT 0
#define RIGHT 1
#define YES 1
#define NO 0

#define MAX_TCP_SESSION_CONNECTION_STORAGE 100

/*Packet Information Array Location assuming VLAN (802.1q) Tag is not included in the Ethernet frame*/
/* If VLAN tag is in the Ethernet frame, then the following protocol field location must be shifted by the length of the VLAN Tag field */
#define IP_HDR_LEN_LOC 14 /*IP Packet header Length */
#define TCP_TYPE_LOC 23 /*TCP packet type */
#define TCP_SRC_PORT 34 /*2 bytes */
#define TCP_DST_PORT 36 /*2 bytes */
#define SEQ_NUM 38 /*4 Bytes */
#define ACK_NUM 42 /*4 Bytes */
#define IP_ADDR_START_LOC_VLAN_TYPE 30
#define IP_ADDR_START_LOC_IP_TYPE 26
#define IP_PKT_SIZE_LOC_VLAN_TYPE 20 /*2 bytes from this location*/
#define IP_PKT_SIZE_LOC_IP_TYPE 16 /*2 bytes from this location*/

// EtherType value
// 0x0800 : IPv4 datagram
// 0x0806 : ARP frame
// 0x8100 : IEEE 802.1Q frame
// 0x86DD : IPv6 frame
#define ETHER_PROTOCOL_TYPE_LOC 12
#define IP_PAYLOAD_TYPE_LOC 23 /*ICMP type, size:1 Byte, value: 0X01 */
#define ICMP_TYPE_LOC 34 /*1 byte */

/*packet information */
#define IP_PAYLOAD_ICMP 1
#define ICMP_REQUEST 8
#define ICMP_REPLY 0
#define VLAN_TYPE 129 /*HEX=81 00*/
#define IP_TYPE 8 /*packet type */
#define NUM_PKT 1000 /*number of packets in a tcpdump file */
#define MAX_PKT_LEN 1700


#if defined(_WIN32)
typedef unsigned int u_int;
#endif

unsigned int pkt_header[4];
unsigned char one_pkt[MAX_PKT_LEN];


struct packet
{
    int length;
};

void ping_response_time_finder(char* in_filename)
{
    FILE* fd;
    unsigned int file_header[6], pkt_header[4], captured_len;
    unsigned char one_pkt[MAX_PKT_LEN];
    int k = 0;
    double start_time, end_time;
    int looking_for_start;

    fd = fopen(in_filename, "rb");
    if (fd < 0) {
        perror("Unable to open input file");
        exit(1);
    }

    if (fread(file_header, sizeof(unsigned int), 6, fd) == 0) {
        perror("File header Error");
        exit(1);
    }

    looking_for_start = YES;

    while (!feof(fd)) {
        for (k = 0; k < MAX_PKT_LEN; k++)
            one_pkt[k] = '\0';

        fread(pkt_header, sizeof(unsigned int), 4, fd);
        captured_len = pkt_header[2];
        if (captured_len == 0) {
            // do nothing
        }
        else {
            if (looking_for_start == YES) {
                fread(&one_pkt[0], sizeof(unsigned char), captured_len, fd);
                start_time = (double)pkt_header[0] + (((double)pkt_header[1]) / 1000000);

                if ((unsigned int)one_pkt[IP_PAYLOAD_TYPE_LOC] == IP_PAYLOAD_ICMP && (unsigned int)one_pkt[ICMP_TYPE_LOC] == ICMP_REQUEST) {
                    looking_for_start = NO;
                }
            }
            else {
                fread(&one_pkt[0], sizeof(unsigned char), captured_len, fd);
                end_time = (double)pkt_header[0] + (((double)pkt_header[1]) / 1000000);

                if ((unsigned int)one_pkt[IP_PAYLOAD_TYPE_LOC] == IP_PAYLOAD_ICMP && (unsigned int)one_pkt[ICMP_TYPE_LOC] == ICMP_REPLY) {
                    looking_for_start = YES;

                    printf("%d.%d.%d.%d %d %f\n", (unsigned int)one_pkt[26], (unsigned int)one_pkt[27],
                        (unsigned int)one_pkt[28], (unsigned int)one_pkt[29], captured_len, end_time - start_time);
                }
            }
        }
    }

    fclose(fd);

} /*end func */


    void fix_frame_len(char* in_filename, char* output_filename)
{
    FILE *fd_in, *fd_out;
    unsigned int file_header[6], pkt_header[4], captured_len;
    unsigned char one_pkt[MAX_PKT_LEN];
    fd_in = fopen(in_filename, "rb");
    if (fd_in < 0) {
        perror("Unable to open input file");
        exit(1);
    }

    fd_out = fopen(output_filename, "wb");
    if (fd_out < 0) {
        perror("Unable to open output file");
        exit(1);
    }

    if (fread(file_header, sizeof(unsigned int), 6, fd_in) == 0) {
        perror("File header Error");
        exit(1);
    }

    fwrite(file_header, sizeof(unsigned int), 6, fd_out);

    while (!feof(fd_in)) {
        fread(pkt_header, sizeof(unsigned int), 4, fd_in);
        captured_len = pkt_header[2];

        if (captured_len > 0) {
            fread(&one_pkt[0], sizeof(unsigned char), captured_len, fd_in);
            if ((unsigned int)one_pkt[ETHER_PROTOCOL_TYPE_LOC] == 0x08) // 0x0800 : IPv4 datagram.
                pkt_header[3] = ((unsigned int)one_pkt[IP_PKT_SIZE_LOC_IP_TYPE] << 8) + (unsigned int)one_pkt[IP_PKT_SIZE_LOC_IP_TYPE + 1] + 14;
            else if ((unsigned int)one_pkt[ETHER_PROTOCOL_TYPE_LOC] == 0x81) // 0x8100 : IEEE 802.1Q frame
                pkt_header[3] = ((unsigned int)one_pkt[IP_PKT_SIZE_LOC_IP_TYPE + 4] << 8) + (unsigned int)one_pkt[IP_PKT_SIZE_LOC_IP_TYPE + 5] + 18;

            if (!feof(fd_in)) {
                fwrite(pkt_header, sizeof(unsigned int), 4, fd_out);
                fwrite(one_pkt, sizeof(unsigned char), captured_len, fd_out);
            }
        }
    }

    fclose(fd_in);
    fclose(fd_out);
}

void ip_address_change(char* in_filename, char* output_filename)
{
    FILE *fd_in, *fd_out;
    unsigned int file_header[6], pkt_header[4], captured_len;
    unsigned char one_pkt[MAX_PKT_LEN];
    unsigned int src_ip_1st_digit, src_ip_2nd_digit, src_ip_3rd_digit, src_ip_4th_digit;
    unsigned int dst_ip_1st_digit, dst_ip_2nd_digit, dst_ip_3rd_digit, dst_ip_4th_digit;
    unsigned int src_port_num, dst_port_num;
    unsigned int seq_n = 0, ack_n = 0;

    fd_in = fopen(in_filename, "rb");
    if (fd_in < 0) {
        perror("Unable to open input file");
        exit(1);
    }

    fd_out = fopen(output_filename, "wb");
    if (fd_out < 0) {
        perror("Unable to open output file");
        exit(1);
    }

    if (fread(file_header, sizeof(unsigned int), 6, fd_in) == 0) {
        perror("File header Error");
        exit(1);
    }

    fwrite(file_header, sizeof(unsigned int), 6, fd_out);

    while (!feof(fd_in)) {
        fread(pkt_header, sizeof(unsigned int), 4, fd_in);
        captured_len = pkt_header[2];

        fread(&one_pkt[0], sizeof(unsigned char), captured_len, fd_in);

        src_ip_1st_digit = (unsigned int)one_pkt[26];
        src_ip_2nd_digit = (unsigned int)one_pkt[27];
        src_ip_3rd_digit = (unsigned int)one_pkt[28];
        src_ip_4th_digit = (unsigned int)one_pkt[29];
        dst_ip_1st_digit = (unsigned int)one_pkt[30];
        dst_ip_2nd_digit = (unsigned int)one_pkt[31];
        dst_ip_3rd_digit = (unsigned int)one_pkt[32];
        dst_ip_4th_digit = (unsigned int)one_pkt[33];

        if (dst_ip_1st_digit == 192 && dst_ip_2nd_digit == 11 && dst_ip_3rd_digit == 68 && dst_ip_4th_digit == 196) {
            one_pkt[30] = 192;
            one_pkt[31] = 11;
            one_pkt[32] = 68;
            one_pkt[33] = 1;
        }

        if (src_ip_1st_digit == 192 && src_ip_2nd_digit == 11 && src_ip_3rd_digit == 68 && src_ip_4th_digit == 196) {
            one_pkt[26] = 192;
            one_pkt[27] = 11;
            one_pkt[28] = 68;
            one_pkt[29] = 1;
        }

        if (!feof(fd_in)) {
            fwrite(pkt_header, sizeof(unsigned int), 4, fd_out);
            fwrite(one_pkt, sizeof(unsigned char), captured_len, fd_out);
        }
    }

    fclose(fd_in);
    fclose(fd_out);
}



void tcp_analysis(char *in_filename, char *out_filename)
{

    FILE *fd_in, *fd_out;
    unsigned int pkt_header[4], captured_len;
    struct packet pac;

    struct packet* aakash = &pac;

        

    fd_in = fopen(in_filename, "rb");
    fd_out = fopen(out_filename, "wb");

    char str[] = "Hello World";
    while (!feof(fd_in)) {
        fread(pkt_header, sizeof(unsigned int), 4, fd_in);
        captured_len = pkt_header[2];
        pac.length = captured_len;

         if (!feof(fd_in)) {
            fwrite(aakash, sizeof(unsigned int), 4, fd_out);
        }
        printf("%x\n",captured_len );
            
        }
fclose(fd_in);
    fclose(fd_out);
    }





















int main(int argc, char* argv[])
{
    printf("Selected Option: %s\n", argv[1]);

    if (strcmp(argv[1], "ping-delay") == 0) {
        ping_response_time_finder(argv[2]);
    }
    else if (strcmp(argv[1], "fix-length") == 0) {
        fix_frame_len(argv[2], argv[3]);
    }
     else if (strcmp(argv[1], "ip-address-change") == 0) {
        ip_address_change(argv[2], argv[3]);
    }
    else if (strcmp(argv[1], "tcp-analysis") == 0) {
        // call your function
        tcp_analysis(argv[2], argv[3]);
    }
    else {
        printf("Four options are available.\n");
        printf("===== Four command line format description =====\n");
        printf("1:  ./pcap-analysis ping-delay input-trace-filename\n");
        printf("2:  ./pcap-analysis fix-length input-trace-filename output-trace-filename\n");
        printf("3:  ./pcap-analysis ip-address-change input-trace-filename output-trace-filename\n");
        printf("4:  ./pcap-analysis tcp-analysis  input-trace-filename  output-filename\n");
        printf("===== END =====\n");
    }
} /*end prog */
