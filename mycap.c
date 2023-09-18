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



// define the values that it needs to be
#define MAX_PKT_LEN 1700 
#define TCP_TYPE_NUM 6

// Define TCP FLAG locations in binary array(starting from 0)

#define ACK 7
#define SYN 10
#define FIN 11


// function to convert Hexadecimal to Binary Number
char* HexToBin(char* hexdec)
{
 
    char result[13] = "000000000000";
    char *s_ptr = result;

    size_t i = (hexdec[1] == 'x' || hexdec[1] == 'X')? 2 : 0;
    int c = 11;
    while (hexdec[i]) {
 
        switch (hexdec[i]) {
            
        case '0':
        result[c-0] = '0';
        result[c-1] = '0';
        result[c-2] = '0';
        result[c-3] = '0';
        c= c-4;
        break;
        case '1':
        result[c-0] = '1';
        result[c-1] = '0';
        result[c-2] = '0';
        result[c-3] = '0';
        c-=4;
            break;
        case '2':
        result[c-0] = '0';
        result[c-1] = '1';
        result[c-2] = '0';
        result[c-3] = '0';
        c-=4;
            break;
        case '3':
        result[c-0] = '1';
        result[c-1] = '1';
        result[c-2] = '0';
        result[c-3] = '0';
        c-=4;
            break;
        case '4':
        result[c-0] = '0';
        result[c-1] = '0';
        result[c-2] = '1';
        result[c-3] = '0';
        c-=4;
            break;
        case '5':
        result[c-0] = '1';
        result[c-1] = '0';
        result[c-2] = '1';
        result[c-3] = '0';
        c-=4;
            break;
        case '6':
        result[c-0] = '0';
        result[c-1] = '1';
        result[c-2] = '1';
        result[c-3] = '0';
        c-=4;
            break;
        case '7':
        result[c-0] = '1';
        result[c-1] = '1';
        result[c-2] = '1';
        result[c-3] = '0';
        c-=4;
            break;
        case '8':
        result[c-0] = '0';
        result[c-1] = '0';
        result[c-2] = '0';
        result[c-3] = '1';
        c-=4;
            break;
        case '9':
        result[c-0] = '1';
        result[c-1] = '0';
        result[c-2] = '0';
        result[c-3] = '1';
        c-=4;
            break;
        case 'A':
        case 'a':
        result[c-0] = '0';
        result[c-1] = '1';
        result[c-2] = '0';
        result[c-3] = '1';
        c-=4;
            break;
        case 'B':
        case 'b':
        result[c-0] = '1';
        result[c-1] = '1';
        result[c-2] = '0';
        result[c-3] = '1';
        c-=4;
            // printf("1011");
            break;
        case 'C':
        case 'c':
        result[c-0] = '0';
        result[c-1] = '0';
        result[c-2] = '1';
        result[c-3] = '1';
        c-=4;
            // printf("1100");
            break;
        case 'D':
        case 'd':
        result[c-0] = '1';
        result[c-1] = '0';
        result[c-2] = '1';
        result[c-3] = '1';
        c-=4;
            // printf("1101");
            break;
        case 'E':
        case 'e':
        result[c-0] = '0';
        result[c-1] = '1';
        result[c-2] = '1';
        result[c-3] = '1';
        c-=4;
            // printf("1110");
            break;
        case 'F':
        case 'f':
        result[c-0] = '1';
        result[c-1] = '1';
        result[c-2] = '1';
        result[c-3] = '1';
        c-=4;
            // printf("1111");
            break;
        case '.':
            printf(".");
        default:
            printf("\nInvalid hexadecimal digit %c",
                   hexdec[i]);
        }
        i++;       
    }
    return(s_ptr);
}

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

void my(char *in_filename){

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

    unsigned int src_ip_1st_digit_FIN, src_ip_2nd_digit_FIN, src_ip_3rd_digit_FIN, src_ip_4th_digit_FIN;
    unsigned int dst_ip_1st_digit_FIN, dst_ip_2nd_digit_FIN, dst_ip_3rd_digit_FIN, dst_ip_4th_digit_FIN;


	if (fd < 0) {
        perror("Unable to open input file");
        exit(1);
    }

    if(fread(file_header, sizeof(unsigned int),6, fd)== 0)
    {
        perror("File header Error");
        exit(1);
    }
    int i =0;
    int k= 0;

    int src_port_num = 0;
    int dst_port_num = 0;

    while (!feof(fd))
    {
        i+=1;
        // read the file header, 4x6 bytes
        fread(pkt_header, sizeof(unsigned int), 4, fd);


        // read the packet header 4x4 bytes
        captured_len =  pkt_header[2];
        fread(&one_pkt[0], sizeof(unsigned char), captured_len, fd);
        
        if((unsigned int)one_pkt[ETHER_PROTOCOL_TYPE_LOC] == (unsigned int)8 & (unsigned int)one_pkt[ETHER_PROTOCOL_TYPE_LOC+1]==0){

            // check if the packet is TCP packet
            if (one_pkt[TCP_TYPE_LOC]==TCP_TYPE_NUM){
                // printf("this is a tcp packet %u \n", captured_len);
                // printf("%d", i);
                
                // char flag_hex = one_pkt[47];
                
                int binarySize;
                int* FLAGS_in_binary = decimalToBinary(one_pkt[47], &binarySize);
                // char FLAGS[13] = "0";
                // check if this packet is SYN
                if (FLAGS_in_binary[SYN]==1){
                    // I need to get the source/destination IP ADDRESSES and the source/destination PORT so that I can check them with the FIN packet and if they are
                    // same, this concludes one TCP session

                    // This is me calculating source/destination IP addresses
                    src_ip_1st_digit = (unsigned int)one_pkt[26];
                    src_ip_2nd_digit = (unsigned int)one_pkt[27];
                    src_ip_3rd_digit = (unsigned int)one_pkt[28];
                    src_ip_4th_digit = (unsigned int)one_pkt[29];
                    dst_ip_1st_digit = (unsigned int)one_pkt[30];
                    dst_ip_2nd_digit = (unsigned int)one_pkt[31];
                    dst_ip_3rd_digit = (unsigned int)one_pkt[32];
                    dst_ip_4th_digit = (unsigned int)one_pkt[33];


                    // THis is me calculating source/destination PORTS
                    src_port_num = (unsigned int)one_pkt[TCP_SRC_PORT];
                    src_port_num = src_port_num << 8;
                    src_port_num += (unsigned int)one_pkt[TCP_SRC_PORT+1];
                    dst_port_num = (unsigned int)one_pkt[TCP_DST_PORT];
                    dst_port_num = dst_port_num << 8;
                    dst_port_num += (unsigned int)one_pkt[TCP_DST_PORT+1];
                    printf("%d \n", src_port_num);
                    // break;



                    k+=1;
                    printf("this is a syn packet ");

                    session_start_time = (double)pkt_header[0] + (((double)pkt_header[1]) / 1000000);
                    printf("%f \n", session_start_time);
                    if(k==2){
                            break;
                    }
                    
                    
                    // break;
                }

                else if(FLAGS_in_binary[FIN]){

                    src_ip_1st_digit_FIN = (unsigned int)one_pkt[26];
                    src_ip_2nd_digit_FIN = (unsigned int)one_pkt[27];
                    src_ip_3rd_digit_FIN = (unsigned int)one_pkt[28];
                    src_ip_4th_digit_FIN= (unsigned int)one_pkt[29];
                    dst_ip_1st_digit_FIN= (unsigned int)one_pkt[30];
                    dst_ip_2nd_digit_FIN = (unsigned int)one_pkt[31];
                    dst_ip_3rd_digit_FIN = (unsigned int)one_pkt[32];
                    dst_ip_4th_digit_FIN = (unsigned int)one_pkt[33];
                    

                    session_end_time = (double)pkt_header[0] + (((double)pkt_header[1]) / 1000000);
                    session_duration = session_end_time-session_start_time

                    printf("This is a fin packet");
                    printf("%d",i);;
                    break;
                }

                // if none of the above I need to do the calculations

                
                

            }
        }
    }



        




        


        



        // check if this is FIN
        // break;
       
    }
    




int main(){
    my("/Users/aakashagarwal/Wireless Communication/cs549/Project/lengthFixed.pcap");
    return(0);
}