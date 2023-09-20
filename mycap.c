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
int hexCharToDecimal(char hexChar) {
    if (hexChar >= '0' && hexChar <= '9') {
        return hexChar - '0';
    } else if (hexChar >= 'A' && hexChar <= 'F') {
        return hexChar - 'A' + 10;
    } else if (hexChar >= 'a' && hexChar <= 'f') {
        return hexChar - 'a' + 10;
    } else {
        // Invalid character
        return -1;
    }
}

int hexStringToDecimal(const char* hexString) {
    int length = strlen(hexString);
    int decimalValue = 0;

    for (int i = length - 1, position = 0; i >= 0; i--, position++) {
        int digitValue = hexCharToDecimal(hexString[i]);
        if (digitValue == -1) {
            printf("Invalid hexadecimal character: %c\n", hexString[i]);
            return -1;
        }
        decimalValue += digitValue * pow(16, position);
    }

    return decimalValue;
}
// function to convert hexadecimal to Decimal Number
int hexToDecimal(int hexadecimal) {
    int decimal = 0;
    int base = 1;

    while (hexadecimal > 0) {
        int remainder = hexadecimal % 10;
        decimal += remainder * base;
        base *= 16;
        hexadecimal /= 10;
    }

    return decimal;
}

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
        
        if((unsigned int)one_pkt[ETHER_PROTOCOL_TYPE_LOC] == (unsigned int)8 & (unsigned int)one_pkt[ETHER_PROTOCOL_TYPE_LOC+1]==0){
            int temp = 0;

            // check if the packet is TCP packet
            if (one_pkt[TCP_TYPE_LOC]==TCP_TYPE_NUM){
                tcp_header_len = (unsigned int)one_pkt[46];
                tcp_header_len = 4*(int) decimalToHexadecimal(tcp_header_len)/10;

                ip_header_len =(unsigned)one_pkt[14];
                ip_header_len = 4*((int)decimalToHexadecimal(ip_header_len)%10);
                
                int check = 0;
                length_IP[0] = (unsigned int)one_pkt[16];
                length_IP[1] = (unsigned int)one_pkt[17];
                length_IP[0] = length_IP[0]<<8;
                length_IP[0]+=length_IP[1];
                len = length_IP[0];
    
                int binarySize;
                int* FLAGS_in_binary = decimalToBinary(one_pkt[47], &binarySize);
                
                src_ip_each[0] = (unsigned int)one_pkt[26];
                src_ip_each[1] = (unsigned int)one_pkt[27];
                src_ip_each[2] = (unsigned int)one_pkt[28];
                src_ip_each[3] = (unsigned int)one_pkt[29];
                dst_ip_each[0] = (unsigned int)one_pkt[30];
                dst_ip_each[1]=  (unsigned int)one_pkt[31];
                dst_ip_each[2] = (unsigned int)one_pkt[32];
                dst_ip_each[3] = (unsigned int)one_pkt[33];


                // THis is me calculating source/destination PORTS
                src_port_num_each = (unsigned int)one_pkt[TCP_SRC_PORT];
                src_port_num_each = src_port_num_each << 8;
                src_port_num_each += (unsigned int)one_pkt[TCP_SRC_PORT+1];
                dst_port_num_each = (unsigned int)one_pkt[TCP_DST_PORT];
                dst_port_num_each = dst_port_num_each << 8;
                dst_port_num_each += (unsigned int)one_pkt[TCP_DST_PORT+1];

                // check if this packet is SYN
                if (FLAGS_in_binary[SYN]==1){  

                    src_ip[0] = (unsigned int)one_pkt[26];
                    src_ip[1] = (unsigned int)one_pkt[27];
                    src_ip[2] = (unsigned int)one_pkt[28];
                    src_ip[3] = (unsigned int)one_pkt[29];
                    dst_ip[0] = (unsigned int)one_pkt[30];
                    dst_ip[1] = (unsigned int)one_pkt[31];
                    dst_ip[2] = (unsigned int)one_pkt[32];
                    dst_ip[3] = (unsigned int)one_pkt[33];


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
                    src_ip_FIN[0] = (unsigned int)one_pkt[26];
                    src_ip_FIN[1] = (unsigned int)one_pkt[27];
                    src_ip_FIN[2] = (unsigned int)one_pkt[28];
                    src_ip_FIN[3] = (unsigned int)one_pkt[29];
                    dst_ip_FIN[0] = (unsigned int)one_pkt[30];
                    dst_ip_FIN[1] = (unsigned int)one_pkt[31];
                    dst_ip_FIN[2] = (unsigned int)one_pkt[32];
                    dst_ip_FIN[3] = (unsigned int)one_pkt[33];


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


        // I will be printing all the information on my file now
        FILE *result;
        result =fopen("hello.txt", "w");
        if (result == NULL) {
                printf("The file is not opened. The program will "
                    "now exit.");
                exit(0);
            }
        fprintf(result,"%s", "TCP Session Count,  ServerIP,  clientIP,  serverPort,  clientPort,  num_of_packetSent(server->client), TotalIPTrafficBytesSent(server->client),  TotalUserTrafficBytesSent(server->client),  sessionDuration,  bits/s_IPlayerthroughput(server->client),  bits/s_Goodput(server->client)\n");
        fprintf(result, "%s", "===============================================================================================================================================================\n");
        for(int index = 0;index<32;index++)
        {

            fprintf(result, "%d \t %d.%d.%d.%d \t %d.%d.%d.%d \t %d \t %d \t %d \t %d \t %d \t %0.3f \t %0.3f \t %0.3f\n", index+1, session_source_ip[4*index], session_source_ip[4*index+1],
             session_source_ip[4*index+2], session_source_ip[4*index+3], session_destination_ip[4*index], session_destination_ip[4*index+1],
             session_destination_ip[4*index+2], session_destination_ip[4*index+3], source_ports[index], destination_ports[index], 
             num_packet_each_session[index], totalIPTrafficByteSent[index], totalUserTrafficByteSent[index], session_duration_each_session[index],
             (8*totalIPTrafficByteSent[index])/session_duration_each_session[index],(8*totalUserTrafficByteSent[index])/session_duration_each_session[index] );


        }




    



        
    



        


        



        // check if this is FIN
        // break;
       
    }
    




int main(){
    my("G:/Wireless Communication/cs549/project1/lengthFixed.pcap");
    return(0);
}