///////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////
//  CIS 549: Wireless Mobile Communications
//  Project #1: Network Packet Manipulation and Packet Trace Analysis
///////////////////////////////////////////
//
// Detailed information is available at the link below
//    https://wiki.wireshark.org/Development/LibpcapFileFormat
//
// Modify TCPDUMP file 
// TCPDUMP file format is 
//
// Global Header < -- The pcap file contains this structure at the beginning.
//
// struct pcap_file_header {
//  unsigned int magic;            4 bytes  //  magic number 
//  unsigned short version_major;  2 bytes  //  major version number 
//  unsigned short version_minor;  2 bytes  //  minor version number
//  unsigned int thiszone;         4 bytes  //  GMT to local correction
//  unsigned int sigfigs;          4 bytes  //  accuracy of timestamps
//  unsigned int snaplen;          4 bytes  //  max length of captured packets, in octets
//  unsigned int linktype;         4 bytes  //  data link type
//  };
//
//
// And then One packet per line in the pcap file
//
// Record (Packet) Header <-- this is not a protocol header
//
// struct pcap_pkthdr{
//  unsigned int time_sec;            4 bytes   //  timestamp seconds
//  unsigned int time_usec;           4 bytes   //  timestamp microseconds
//  unsigned int captured_len;        4 bytes   //  number of octets of packet saved in file
//  unsigned int off_wire_pkt_length; 4 bytes   //  actual length of packet
//  };
//
// Wireshark displays following information only in the Frame View
// struct captured_packet {     Total size of this structure is same as captured_len above.
//    source MAC address                 6 bytes
//    Destination MAC address            6 bytes
//    Packet type (IP packet = 8)        2 bytes
//    IP header length(if pkt type is IP)1 bytes
//     ........
//
// REPEAT "pacp_pkthdr" and "captured_packet" structures until the end of the captured file.
//
////////////////////////////////////////////////////////////////////////////////////////////////

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
#define SHIFT 4
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

// #include <pcap.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <math.h>

// define the byte places
#define TCP_TYPE_LOC 23 /*TCP packet type */
#define TCP_SRC_PORT 34 /*2 bytes */
#define TCP_DST_PORT 36 /*2 bytes */
#define SEQ_NUM 38 /*4 Bytes */
#define ACK_NUM 42 /*4 Bytes */
#define IP_ADDR_START_LOC_IP_TYPE 26
#define IP_PKT_SIZE_LOC_VLAN_TYPE 20 /*2 bytes from this location*/
#define IP_PKT_SIZE_LOC_IP_TYPE 16 /*2 bytes from this location*/
#define TCP_HEADER_LEN 46
#define IP_HEADER_LEN 14
#define TCP_FLAGS 47

// EtherType value
// 0x0800 : IPv4 datagram
// 0x0806 : ARP frame
// 0x8100 : IEEE 802.1Q frame
// 0x86DD : IPv6 frame
#define ETHER_PROTOCOL_TYPE_LOC 12
#define IP_PAYLOAD_TYPE_LOC 23 /*ICMP type, size:1 Byte, value: 0X01 */
#define ICMP_TYPE_LOC 34 /*1 byte */



// define the values that it needs to be
#define MAX_PKT_LEN 1700 
#define TCP_TYPE_NUM 6

// Define TCP FLAG locations in binary array(starting from 0)

#define ACK 7
#define SYN 10
#define FIN 11




// function to convert Decimal to Hexadecimal to decimal Number
int decimalToHexadecimal(int decimalNumber) {
    int hexadecimalNumber = 0;
    int base = 1;

    while (decimalNumber > 0) {
        int remainder = decimalNumber % 16;
        hexadecimalNumber += remainder * base;
        base *= 10;
        decimalNumber /= 16;
    }

    return hexadecimalNumber;
}

// function to convert Hexadecimal to Binary Number


int* decimalToBinary(int decimal, int* binarySize) {
    int i;

    // Calculate the number of bits required for the binary representation
    int temp = decimal;
    int numBits = 0;
    while (temp > 0) {
        temp /= 2;
        numBits++;
    }

    // Ensure a minimum of 12 bits
    if (numBits < 12) {
        numBits = 12;
    }

    // Create the binary array dynamically
    int* binaryArray = (int*)malloc(numBits * sizeof(int));
    if (binaryArray == NULL) {
        fprintf(stderr, "Memory allocation failed.\n");
        exit(1);
    }

    // Initialize the binary array to all zeros
    for (i = 0; i < numBits; i++) {
        binaryArray[i] = 0;
    }

    // Convert decimal to binary
    for (i = numBits - 1; i >= 0 && decimal > 0; i--) {
        binaryArray[i] = decimal % 2;
        decimal /= 2;
    }

    *binarySize = numBits;
    return binaryArray;
}

#if defined(_WIN32)
typedef unsigned int u_int;
#endif

unsigned int pkt_header[4];
unsigned char one_pkt[MAX_PKT_LEN];



unsigned int bits_to_ui(char* x, int byte_count, int order)
/*********************************************/
/* Convert bits to unsigned int  */
/*********************************************/
{
    unsigned int displayMask = 1;
    int i, j, location = 0;
    unsigned int result = 0;

    if (order == 0) {
        for (j = byte_count - 1; j >= 0; j--) {
            for (i = 1; i <= 8; i++) {
                if (x[j] & displayMask) {
                    result = result + pow(2, location);
                    //printf("1");
                }
                else {
                    //printf("0");
                }

                location++;
                x[j] >>= 1;
            }
        }

        //printf("\n");
    }
    else {
        for (j = 0; j < byte_count; j++) {
            for (i = 1; i <= 8; i++) {
                if (x[j] & displayMask)
                    result = result + pow(2, location);
                location++;
                x[j] >>= 1;
            }
        }
    }

    return result;
}

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
    int flag_very = 0;
	FILE *fd;
    double a = 0;
	fd = fopen(in_filename, "rb");
	unsigned int file_header[6], pkt_header[4], captured_len;
    double session_start_time = 0;
    double session_end_time = 0;
    double session_duration = 0;

    unsigned char one_pkt[MAX_PKT_LEN];
    unsigned int byte_13 = 0;
    unsigned int byte_14 = 0;
    unsigned int src_ip_1st_digit, src_ip_2nd_digit, src_ip_3rd_digit, src_ip_4th_digit;
    unsigned int dst_ip_1st_digit, dst_ip_2nd_digit, dst_ip_3rd_digit, dst_ip_4th_digit;

    unsigned int src_ip[4] = {0,0,0,0};
    unsigned int dst_ip[4] = {0,0,0,0};

    unsigned int src_ip_FIN[4] = {0,0,0,0}; 
    unsigned int dst_ip_FIN[4] = {0,0,0,0}; 

    unsigned int src_ip_each[4] = {0,0,0,0};
    unsigned int dst_ip_each[4] = {0,0,0,0};


    int session_source_ip[140];
    int session_destination_ip[140];


    int src_port_num = 0;
    int dst_port_num = 0;

    int src_port_num_FIN = 0;
    int dst_port_num_FIN = 0;

    int src_port_num_each = 0;
    int dst_port_num_each = 0;

    int session_id = 0;
    int total_tcp_header_len = 0;
    int total_ip_header_len = 0;
    int tcp_header_len=0;
    int ip_header_len=0;
    int num_packet_each_session[35];
    double session_duration_each_session[35];
    int totalIPTrafficByteSent[35];
    int totalUserTrafficByteSent[35];
    int source_ports[35];
    int destination_ports[35];
    


    for(int m=0;m<36;m++){
        num_packet_each_session[m]=0;
    }

	if (fd < 0) {
        perror("Unable to open input file");
        exit(1);
    }

    if(fread(file_header, sizeof(unsigned int),6, fd)== 0)
    {
        perror("File header Error");
        exit(1);
    }
    
    int k= 0;
    int total_len = 0;
    int SYN_FLAG =0;
    int fini=0;
    int i =0;
    int length_IP[2] = {0, 0};
    while (!feof(fd))
    {
        
        unsigned int len = 0;
        // read the file header, 4x6 bytes
        fread(pkt_header, sizeof(unsigned int), 4, fd);


        // read the packet header 4x4 bytes
        captured_len =  pkt_header[2];
        fread(&one_pkt[0], sizeof(unsigned char), captured_len, fd);
        if ((unsigned int)one_pkt[12]==(unsigned int)129& (unsigned int)one_pkt[ETHER_PROTOCOL_TYPE_LOC+1]==0)
        {
            flag_very = 1;
            // this contains vlan
            // check if the packet is TCP packet
            if (one_pkt[TCP_TYPE_LOC+SHIFT]==TCP_TYPE_NUM){
                tcp_header_len = (unsigned int)one_pkt[TCP_HEADER_LEN+SHIFT];
                tcp_header_len = 4*(int) decimalToHexadecimal(tcp_header_len)/10;

                ip_header_len =(unsigned)one_pkt[IP_HEADER_LEN+SHIFT];
                ip_header_len = 4*((int)decimalToHexadecimal(ip_header_len)%10);
                
                int check = 0;
                length_IP[0] = (unsigned int)one_pkt[IP_PKT_SIZE_LOC_IP_TYPE+SHIFT];
                length_IP[1] = (unsigned int)one_pkt[IP_PKT_SIZE_LOC_IP_TYPE+1+SHIFT];
                length_IP[0] = length_IP[0]<<8;
                length_IP[0]+=length_IP[1];
                len = length_IP[0];
    
                int binarySize;
                int* FLAGS_in_binary = decimalToBinary(one_pkt[TCP_FLAGS+SHIFT], &binarySize);
                
                src_ip_each[0] = (unsigned int)one_pkt[IP_ADDR_START_LOC_IP_TYPE+SHIFT];
                src_ip_each[1] = (unsigned int)one_pkt[IP_ADDR_START_LOC_IP_TYPE+1+SHIFT];
                src_ip_each[2] = (unsigned int)one_pkt[IP_ADDR_START_LOC_IP_TYPE+2+SHIFT];
                src_ip_each[3] = (unsigned int)one_pkt[IP_ADDR_START_LOC_IP_TYPE+3+SHIFT];
                dst_ip_each[0] = (unsigned int)one_pkt[IP_ADDR_START_LOC_IP_TYPE+4+SHIFT];
                dst_ip_each[1]=  (unsigned int)one_pkt[IP_ADDR_START_LOC_IP_TYPE+5+SHIFT];
                dst_ip_each[2] = (unsigned int)one_pkt[IP_ADDR_START_LOC_IP_TYPE+6+SHIFT];
                dst_ip_each[3] = (unsigned int)one_pkt[IP_ADDR_START_LOC_IP_TYPE+7+SHIFT];


                // THis is me calculating source/destination PORTS
                src_port_num_each = (unsigned int)one_pkt[TCP_SRC_PORT+SHIFT];
                src_port_num_each = src_port_num_each << 8;
                src_port_num_each += (unsigned int)one_pkt[TCP_SRC_PORT+1+SHIFT];
                dst_port_num_each = (unsigned int)one_pkt[TCP_DST_PORT+SHIFT];
                dst_port_num_each = dst_port_num_each << 8;
                dst_port_num_each += (unsigned int)one_pkt[TCP_DST_PORT+1+SHIFT];

                // check if this packet is SYN
                if (FLAGS_in_binary[SYN]==1){  

                    src_ip[0] = (unsigned int)one_pkt[IP_ADDR_START_LOC_IP_TYPE+SHIFT];
                    src_ip[1] = (unsigned int)one_pkt[IP_ADDR_START_LOC_IP_TYPE+1+SHIFT];
                    src_ip[2] = (unsigned int)one_pkt[IP_ADDR_START_LOC_IP_TYPE+2+SHIFT];
                    src_ip[3] = (unsigned int)one_pkt[IP_ADDR_START_LOC_IP_TYPE+3+SHIFT];
                    dst_ip[0] = (unsigned int)one_pkt[IP_ADDR_START_LOC_IP_TYPE+4+SHIFT];
                    dst_ip[1] = (unsigned int)one_pkt[IP_ADDR_START_LOC_IP_TYPE+5+SHIFT];
                    dst_ip[2] = (unsigned int)one_pkt[IP_ADDR_START_LOC_IP_TYPE+6+SHIFT];
                    dst_ip[3] = (unsigned int)one_pkt[IP_ADDR_START_LOC_IP_TYPE+7+SHIFT];


                    // THis is me calculating source/destination PORTS
                    src_port_num = (unsigned int)one_pkt[TCP_SRC_PORT+SHIFT];
                    src_port_num = src_port_num << 8;
                    src_port_num += (unsigned int)one_pkt[TCP_SRC_PORT+1+SHIFT];
                    dst_port_num = (unsigned int)one_pkt[TCP_DST_PORT+SHIFT];
                    dst_port_num = dst_port_num << 8;
                    dst_port_num += (unsigned int)one_pkt[TCP_DST_PORT+1+SHIFT];
                    
                    if (src_port_num!=80){
                        continue;
                    }
                        i+=1;
                        session_start_time = (double)pkt_header[0] + (((double)pkt_header[1]) / 1000000);
                        total_tcp_header_len+=tcp_header_len;
                        total_ip_header_len+=ip_header_len;
                        total_len+=len;
                }
                
                else if(FLAGS_in_binary[FIN]){

                    src_ip_FIN[0] = (unsigned int)one_pkt[IP_ADDR_START_LOC_IP_TYPE+SHIFT];
                    src_ip_FIN[1] = (unsigned int)one_pkt[IP_ADDR_START_LOC_IP_TYPE+1+SHIFT];
                    src_ip_FIN[2] = (unsigned int)one_pkt[IP_ADDR_START_LOC_IP_TYPE+2+SHIFT];
                    src_ip_FIN[3] = (unsigned int)one_pkt[IP_ADDR_START_LOC_IP_TYPE+3+SHIFT];
                    dst_ip_FIN[0] = (unsigned int)one_pkt[IP_ADDR_START_LOC_IP_TYPE+4+SHIFT];
                    dst_ip_FIN[1] = (unsigned int)one_pkt[IP_ADDR_START_LOC_IP_TYPE+5+SHIFT];
                    dst_ip_FIN[2] = (unsigned int)one_pkt[IP_ADDR_START_LOC_IP_TYPE+6+SHIFT];
                    dst_ip_FIN[3] = (unsigned int)one_pkt[IP_ADDR_START_LOC_IP_TYPE+7+SHIFT];


                    src_port_num_FIN = (unsigned int)one_pkt[TCP_SRC_PORT+SHIFT];
                    src_port_num_FIN = src_port_num_FIN << 8;
                    src_port_num_FIN += (unsigned int)one_pkt[TCP_SRC_PORT+1+SHIFT];
                    dst_port_num_FIN = (unsigned int)one_pkt[TCP_DST_PORT+SHIFT];
                    dst_port_num_FIN = dst_port_num_FIN << 8;
                    dst_port_num_FIN += (unsigned int)one_pkt[TCP_DST_PORT+1+SHIFT];
                    
                   
                    // check if the fin packet is of the same source ip and destination ip
                    
                    if ((src_ip_FIN[0]==src_ip[0]) && (src_ip_FIN[1]==src_ip[1]) && (src_ip_FIN[2] == src_ip[2])
                    && ( src_ip_FIN[3] == src_ip[3])
                    && (dst_ip_FIN[0] ==dst_ip[0]) && (dst_ip_FIN[1]==dst_ip[1]) && (dst_ip_FIN[2] == dst_ip[2])
                    && ( dst_ip_FIN[3] == dst_ip[3])
                    && (src_port_num==src_port_num_FIN) && (dst_port_num==dst_port_num_FIN)){

                        i+=1;
                        session_end_time = (double)pkt_header[0] + (((double)pkt_header[1]) / 1000000);
                        session_duration = session_end_time-session_start_time;
                        total_tcp_header_len+=tcp_header_len;
                        total_ip_header_len+=ip_header_len;

                        total_len+=len;
                        
                        session_source_ip[4*session_id+0]= src_ip_FIN[0];
                        session_source_ip[4*session_id+1]= src_ip_FIN[1];
                        session_source_ip[4*session_id+2]= src_ip_FIN[2];
                        session_source_ip[4*session_id+3]= src_ip_FIN[3];
                        
                        session_destination_ip[4*session_id+0]= dst_ip_FIN[0];
                        session_destination_ip[4*session_id+1]= dst_ip_FIN[1];
                        session_destination_ip[4*session_id+2]= dst_ip_FIN[2];
                        session_destination_ip[4*session_id+3]= dst_ip_FIN[3];


                        totalUserTrafficByteSent[session_id] = total_len-(total_ip_header_len+total_tcp_header_len);
                        source_ports[session_id]=src_port_num;
                        destination_ports[session_id] = dst_port_num;
                        num_packet_each_session[session_id] = i;
                        session_duration_each_session[session_id] = session_duration;
                        totalIPTrafficByteSent[session_id] = total_len;
                        session_id+=1;

                        total_len=0;
                        total_ip_header_len=0;
                        total_tcp_header_len=0;
                        i=0;
                    } 

                }

                // if none of the above I need to do the calculations
                else{
                    if(src_ip[0]==src_ip_each[0] && src_ip[1]== src_ip_each[1] && src_ip[2] ==src_ip_each[2]
                    && src_ip[3]==src_ip_each[3]){
                    
                        i+=1;
                        total_tcp_header_len+=tcp_header_len;
                        total_ip_header_len+=ip_header_len;
                        total_len+=len;
                    }
                }
            }
            
        }
        else{
        if((unsigned int)one_pkt[ETHER_PROTOCOL_TYPE_LOC] == (unsigned int)8 & (unsigned int)one_pkt[ETHER_PROTOCOL_TYPE_LOC+1]==0){
            int temp = 0;

            // check if the packet is TCP packet
            if (one_pkt[TCP_TYPE_LOC]==TCP_TYPE_NUM){
                tcp_header_len = (unsigned int)one_pkt[TCP_HEADER_LEN];
                tcp_header_len = 4*(int) decimalToHexadecimal(tcp_header_len)/10;

                ip_header_len =(unsigned)one_pkt[IP_HEADER_LEN];
                ip_header_len = 4*((int)decimalToHexadecimal(ip_header_len)%10);
                
                int check = 0;
                length_IP[0] = (unsigned int)one_pkt[IP_PKT_SIZE_LOC_IP_TYPE];
                length_IP[1] = (unsigned int)one_pkt[IP_PKT_SIZE_LOC_IP_TYPE+1];
                length_IP[0] = length_IP[0]<<8;
                length_IP[0]+=length_IP[1];
                len = length_IP[0];
    
                int binarySize;
                int* FLAGS_in_binary = decimalToBinary(one_pkt[TCP_FLAGS], &binarySize);
                
                src_ip_each[0] = (unsigned int)one_pkt[IP_ADDR_START_LOC_IP_TYPE];
                src_ip_each[1] = (unsigned int)one_pkt[IP_ADDR_START_LOC_IP_TYPE+1];
                src_ip_each[2] = (unsigned int)one_pkt[IP_ADDR_START_LOC_IP_TYPE+2];
                src_ip_each[3] = (unsigned int)one_pkt[IP_ADDR_START_LOC_IP_TYPE+3];
                dst_ip_each[0] = (unsigned int)one_pkt[IP_ADDR_START_LOC_IP_TYPE+4];
                dst_ip_each[1]=  (unsigned int)one_pkt[IP_ADDR_START_LOC_IP_TYPE+5];
                dst_ip_each[2] = (unsigned int)one_pkt[IP_ADDR_START_LOC_IP_TYPE+6];
                dst_ip_each[3] = (unsigned int)one_pkt[IP_ADDR_START_LOC_IP_TYPE+7];


                // THis is me calculating source/destination PORTS
                src_port_num_each = (unsigned int)one_pkt[TCP_SRC_PORT];
                src_port_num_each = src_port_num_each << 8;
                src_port_num_each += (unsigned int)one_pkt[TCP_SRC_PORT+1];
                dst_port_num_each = (unsigned int)one_pkt[TCP_DST_PORT];
                dst_port_num_each = dst_port_num_each << 8;
                dst_port_num_each += (unsigned int)one_pkt[TCP_DST_PORT+1];

                // check if this packet is SYN
                if (FLAGS_in_binary[SYN]==1){  

                    src_ip[0] = (unsigned int)one_pkt[IP_ADDR_START_LOC_IP_TYPE];
                    src_ip[1] = (unsigned int)one_pkt[IP_ADDR_START_LOC_IP_TYPE+1];
                    src_ip[2] = (unsigned int)one_pkt[IP_ADDR_START_LOC_IP_TYPE+2];
                    src_ip[3] = (unsigned int)one_pkt[IP_ADDR_START_LOC_IP_TYPE+3];
                    dst_ip[0] = (unsigned int)one_pkt[IP_ADDR_START_LOC_IP_TYPE+4];
                    dst_ip[1] = (unsigned int)one_pkt[IP_ADDR_START_LOC_IP_TYPE+5];
                    dst_ip[2] = (unsigned int)one_pkt[IP_ADDR_START_LOC_IP_TYPE+6];
                    dst_ip[3] = (unsigned int)one_pkt[IP_ADDR_START_LOC_IP_TYPE+7];


                    // THis is me calculating source/destination PORTS
                    src_port_num = (unsigned int)one_pkt[TCP_SRC_PORT];
                    src_port_num = src_port_num << 8;
                    src_port_num += (unsigned int)one_pkt[TCP_SRC_PORT+1];
                    dst_port_num = (unsigned int)one_pkt[TCP_DST_PORT];
                    dst_port_num = dst_port_num << 8;
                    dst_port_num += (unsigned int)one_pkt[TCP_DST_PORT+1];
                    
                    if (src_port_num!=80){
                        continue;
                    }
                        i+=1;
                        session_start_time = (double)pkt_header[0] + (((double)pkt_header[1]) / 1000000);
                        total_tcp_header_len+=tcp_header_len;
                        total_ip_header_len+=ip_header_len;
                        total_len+=len;
                }
                
                else if(FLAGS_in_binary[FIN]){
                    // printf("%d\n", src_port_num_each);                        
                    src_ip_FIN[0] = (unsigned int)one_pkt[IP_ADDR_START_LOC_IP_TYPE];
                    src_ip_FIN[1] = (unsigned int)one_pkt[IP_ADDR_START_LOC_IP_TYPE+1];
                    src_ip_FIN[2] = (unsigned int)one_pkt[IP_ADDR_START_LOC_IP_TYPE+2];
                    src_ip_FIN[3] = (unsigned int)one_pkt[IP_ADDR_START_LOC_IP_TYPE+3];
                    dst_ip_FIN[0] = (unsigned int)one_pkt[IP_ADDR_START_LOC_IP_TYPE+4];
                    dst_ip_FIN[1] = (unsigned int)one_pkt[IP_ADDR_START_LOC_IP_TYPE+5];
                    dst_ip_FIN[2] = (unsigned int)one_pkt[IP_ADDR_START_LOC_IP_TYPE+6];
                    dst_ip_FIN[3] = (unsigned int)one_pkt[IP_ADDR_START_LOC_IP_TYPE+7];


                    src_port_num_FIN = (unsigned int)one_pkt[TCP_SRC_PORT];
                    src_port_num_FIN = src_port_num_FIN << 8;
                    src_port_num_FIN += (unsigned int)one_pkt[TCP_SRC_PORT+1];
                    dst_port_num_FIN = (unsigned int)one_pkt[TCP_DST_PORT];
                    dst_port_num_FIN = dst_port_num_FIN << 8;
                    dst_port_num_FIN += (unsigned int)one_pkt[TCP_DST_PORT+1];
                    
                   
                    // check if the fin packet is of the same source ip and destination ip
                    
                    if ((src_ip_FIN[0]==src_ip[0]) && (src_ip_FIN[1]==src_ip[1]) && (src_ip_FIN[2] == src_ip[2])
                    && ( src_ip_FIN[3] == src_ip[3])
                    && (dst_ip_FIN[0] ==dst_ip[0]) && (dst_ip_FIN[1]==dst_ip[1]) && (dst_ip_FIN[2] == dst_ip[2])
                    && ( dst_ip_FIN[3] == dst_ip[3])
                    && (src_port_num==src_port_num_FIN) && (dst_port_num==dst_port_num_FIN)){

                        i+=1;
                        session_end_time = (double)pkt_header[0] + (((double)pkt_header[1]) / 1000000);
                        session_duration = session_end_time-session_start_time;
                        total_tcp_header_len+=tcp_header_len;
                        total_ip_header_len+=ip_header_len;

                        total_len+=len;
                        
                        session_source_ip[4*session_id+0]= src_ip_FIN[0];
                        session_source_ip[4*session_id+1]= src_ip_FIN[1];
                        session_source_ip[4*session_id+2]= src_ip_FIN[2];
                        session_source_ip[4*session_id+3]= src_ip_FIN[3];
                        
                        session_destination_ip[4*session_id+0]= dst_ip_FIN[0];
                        session_destination_ip[4*session_id+1]= dst_ip_FIN[1];
                        session_destination_ip[4*session_id+2]= dst_ip_FIN[2];
                        session_destination_ip[4*session_id+3]= dst_ip_FIN[3];


                        totalUserTrafficByteSent[session_id] = total_len-(total_ip_header_len+total_tcp_header_len);
                        source_ports[session_id]=src_port_num;
                        destination_ports[session_id] = dst_port_num;
                        num_packet_each_session[session_id] = i;
                        session_duration_each_session[session_id] = session_duration;
                        totalIPTrafficByteSent[session_id] = total_len;
                        session_id+=1;

                        total_len=0;
                        total_ip_header_len=0;
                        total_tcp_header_len=0;
                        i=0;
                    } 

                }

                // if none of the above I need to do the calculations
                else{
                    if(src_ip[0]==src_ip_each[0] && src_ip[1]== src_ip_each[1] && src_ip[2] ==src_ip_each[2]
                    && src_ip[3]==src_ip_each[3]){
                    
                        i+=1;
                        total_tcp_header_len+=tcp_header_len;
                        total_ip_header_len+=ip_header_len;
                        total_len+=len;
                    }
                }
            }
        }
        }

    }


        // I will be printing all the information on my file now
        FILE *result;
        result =fopen(out_filename, "w");
        if (result == NULL) {
                printf("The file is not opened. The program will "
                    "now exit.");
                exit(0);
            }
        fprintf(result,"%s", "TCP Session Count,  ServerIP,  clientIP,  serverPort,  clientPort,  num_of_packetSent(server->client), TotalIPTrafficBytesSent(server->client),  TotalUserTrafficBytesSent(server->client),  sessionDuration,  bits/s_IPlayerthroughput(server->client),  bits/s_Goodput(server->client)\n");
        fprintf(result, "%s", "===============================================================================================================================================================\n");
        for(int index = 0;index<32+flag_very;index++)
        {

            fprintf(result, "%d \t %d.%d.%d.%d \t %d.%d.%d.%d \t %d \t %d \t %d \t %d \t %d \t %0.3f \t %0.3f \t %0.3f\n", index+1, session_source_ip[4*index], session_source_ip[4*index+1],
             session_source_ip[4*index+2], session_source_ip[4*index+3], session_destination_ip[4*index], session_destination_ip[4*index+1],
             session_destination_ip[4*index+2], session_destination_ip[4*index+3], source_ports[index], destination_ports[index], 
             num_packet_each_session[index], totalIPTrafficByteSent[index], totalUserTrafficByteSent[index], session_duration_each_session[index],
             (8*totalIPTrafficByteSent[index])/session_duration_each_session[index],(8*totalUserTrafficByteSent[index])/session_duration_each_session[index] );


        } 
    }



int main(int argc, char* argv[])
{
    tcp_analysis("G:/Wireless Communication/cs549/project1/lengthFixed.pcap","output.txt");


    // printf("Selected Option: %s\n", argv[1]);

    // if (strcmp(argv[1], "ping-delay") == 0) {
    //     ping_response_time_finder(argv[2]);
    // }
    // else if (strcmp(argv[1], "fix-length") == 0) {
    //     fix_frame_len(argv[2], argv[3]);
    // }
    //  else if (strcmp(argv[1], "ip-address-change") == 0) {
    //     ip_address_change(argv[2], argv[3]);
    // }
    // else if (strcmp(argv[1], "tcp-analysis") == 0) {
    //     // call your function
    //     tcp_analysis(argv[2], argv[3]);
    // }
    // else {
    //     printf("Four options are available.\n");
    //     printf("===== Four command line format description =====\n");
    //     printf("1:  ./pcap-analysis ping-delay input-trace-filename\n");
    //     printf("2:  ./pcap-analysis fix-length input-trace-filename output-trace-filename\n");
    //     printf("3:  ./pcap-analysis ip-address-change input-trace-filename output-trace-filename\n");
    //     printf("4:  ./pcap-analysis tcp-analysis  input-trace-filename  output-filename\n");
    //     printf("===== END =====\n");
    // }
} /*end prog */

