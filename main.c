/**
* @Author xiyuan
* @Date 2021/12/5 14:14
* @Version 1.0
*/
#pragma comment(lib, "ws2_32.lib")

#include <stdio.h>
#include <malloc.h>
#include <io.h>
#include <winsock2.h>
#include "struct/pcap.h"

#define PCAP_FILE "C://Users//86158//Desktop//school//111.pcap"
//#define PCAP_FILE "C://Users//86158//Desktop//school//udp.pcap"
//#define PCAP_FILE "C://Users//86158//Desktop//school//RIP.pcap"
#define PCAP_FILE2 "C://Users//86158//Desktop//222.pcap"

#define MAX_ETH_FRAME 1514

void analysisPcap() {
    pcap_file_header pfh;
    pcap_header ph;
    void *pcap_head = NULL;
    int readSize = 0;

    FILE *fp = fopen(PCAP_FILE, "rb");//w r
    fseek(fp, 0, SEEK_END);
    int i = ftell(fp);
    fseek(fp, 0, 0);
    if (fp == NULL) {
        fprintf(stderr, "Open file %s error.", PCAP_FILE);
        return;
    }
    //��fp���ļ��е����ݶ���pfh��ȥ
    fread(&pfh, sizeof(pcap_file_header), 1, fp);
    prinfPcapFileHeader(&pfh);
    //�����buff�����ڴ�����벢�ҽ��г�ʼ��
    pcap_head = (void *) malloc(MAX_ETH_FRAME);
    memset(pcap_head, 0, MAX_ETH_FRAME);
    readSize = fread(&ph, sizeof(pcap_header), 1, fp);
    if (readSize <= 0) {
        return;
    }
    printfPcapHeader(&ph);
    //��̫��ͷ��
    void *ethernet = NULL;
    ethernet = (void *) malloc(sizeof(ethernet_header));//Ҫ�����ڴ�
    readSize = fread(ethernet, sizeof(ethernet_header), 1, fp);
    if (readSize == 0)
        return;
    printfEthernetHeader(ethernet);
    //IP���ݰ�
    void *IP_data = NULL;
    IP_data = (void *) malloc(sizeof(ipHeader));//Ҫ�����ڴ�
    readSize = fread(IP_data, sizeof(ipHeader), 1, fp);
    if (readSize == 0)
        return;
    int a = printfIpHeader(IP_data);
    //tcp���ݰ�
    if (a == 6) {
        void *TCP_data = NULL;
        TCP_data = (void *) malloc(sizeof(tcpHeader));//Ҫ�����ڴ�
        readSize = fread(TCP_data, sizeof(tcpHeader), 1, fp);
        if (readSize == 0)
            return;
        struct tcp_check_head tcpCheckHead = printfTcpHeader(TCP_data);
        uint16_t check = tcpCheckHead.tcp_checksum;
        tcpCheckHead.tcp_checksum = 0;
        int size = i - (sizeof(tcpHeader) + sizeof(ipHeader) + sizeof(ethernet_header) + sizeof(pcap_header) +
                        sizeof(pcap_file_header));
        int arr_size;
        tcpCheckHead.len = ntohs(size + sizeof(struct tcp_header));
        if (size % 2 == 1)
            arr_size = size + 1;
        else
            arr_size = size;
        char message_data[arr_size];
        int j;
        for (j = 0; j < size; ++j) {
            message_data[j] = fp->_ptr[j];
        }
//        message_data[size - 2] = 0x0d;
//        fread(message_data, size, 1, fp);
        printf("���ĳ���%d\n", size);
        int buf_size = size + sizeof(struct tcp_check_head);
        if (size % 2 == 1) {
            message_data[j] = 0;
            buf_size++;
        }
//        char *buffer = (char *) malloc(buf_size);
        char buffer[buf_size];
        memcpy(buffer, &tcpCheckHead, sizeof(tcpCheckHead));
        memcpy_s(buffer + sizeof(tcpCheckHead), buf_size, message_data, size);
        if (check == ntohs(checksum(&buffer, buf_size)))
            printf("tcpУ�������\n");
        else
            printf("У�������\n");
    }
    //udp���ݰ�
    if (a == 17) {
        void *UDP_data = NULL;
        UDP_data = (void *) malloc(sizeof(udpHeader));//Ҫ�����ڴ�
        readSize = fread(UDP_data, sizeof(udpHeader), 1, fp);
        if (readSize == 0)
            return;
        struct check_udp_header checkUdpHeader = printfUdpHeader(UDP_data);
        uint16_t check = checkUdpHeader.udp_checksum;
        checkUdpHeader.udp_checksum = 0;
        int size = i - (sizeof(struct udp_header) + sizeof(ipHeader) + sizeof(ethernet_header) + sizeof(pcap_header) +
                        sizeof(pcap_file_header));
        int arr_size;
        if (size % 2 == 1)
            arr_size = size + 1;
        else
            arr_size = size;
        char message_data[arr_size];
        int j;
        for (j = 0; j < size; ++j) {
            message_data[j] = fp->_ptr[j];
        }
//        message_data[size - 2] = 0x0d;
        int buf_size = size + sizeof(struct check_udp_header);
        if (size % 2 == 1) {
            message_data[j] = 0;
            buf_size++;
        }
        char buffer[buf_size];
        memcpy(buffer, &checkUdpHeader, sizeof(checkUdpHeader));
        memcpy_s(buffer + sizeof(checkUdpHeader), buf_size, message_data, size);
//        printf("%x\n",checksum(&buffer, buf_size));
//        printf("%x\n",check);
        if (check == checksum(&buffer, buf_size))
            printf("ucpУ�������\n");
        else
            printf("udpУ�������\n");
    }
    fclose(fp);
}

char data[] = "\x32\x32\x30\x20\x6e\x65\x77\x78\x6d\x65\x73\x6d\x74\x70\x6c\x6f\x67\x69\x63\x73\x76\x72\x73\x7a\x61\x35\x2e\x71\x71\x2e\x63\x6f\x6d\x20\x58\x4d\x61\x69\x6c\x20\x45\x73\x6d\x74\x70\x20\x51\x51\x20\x4d\x61\x69\x6c\x20\x53\x65\x72\x76\x65\x72\x2e\x0d\x0d";

void createPcap() {
//    printf("%d", strlen(data));
    FILE *fp = fopen(PCAP_FILE2, "w");
    pcap_file_header pcapFileHeader;
    createPcapFileHeader(&pcapFileHeader);
    fwrite(&pcapFileHeader, sizeof(pcap_file_header), 1, fp);
//pcapͷ��
    pcap_header pcap_header;
    createPcapHeader(&pcap_header);
    fwrite(&pcap_header, sizeof(pcap_header), 1, fp);
//ethernetͷ��
    struct ethernet_header ethernetHeader;
    createEthernetHeader(&ethernetHeader);
    fwrite(&ethernetHeader, sizeof(ethernetHeader), 1, fp);
//����ipͷ��
    struct ip_header ipHeader;
    createIpHeader(&ipHeader);
    fwrite(&ipHeader, sizeof(ipHeader), 1, fp);
//����tcpͷ��
    struct tcp_header tcp_header;
    createTcpHeader(&tcp_header, sizeof(data) - 1, data);
    fwrite(&tcp_header, sizeof(tcp_header), 1, fp);
//����һЩ����
//    char *data;//������Ǹ�����
//    int size = createData(&data);//�����С
//    for (int i = 0; i < size; ++i) {
//        fwrite(&data+i, 1, 1, fp);//д���ļ�
//    }
    fwrite(&data, sizeof(data) - 1, 1, fp);
    fclose(fp);

}


void main() {

//    printf("sizeof:int %lu,unsigned int %lu,char %lu,unsigned char %lu,short:%lu,unsigned short:%lu\n",
//           sizeof(int), sizeof(unsigned int), sizeof(char), sizeof(unsigned char), sizeof(short),
//           sizeof(unsigned short));
//
    while (1) {
        printf("1.����pcap����\n");
        printf("2.����pcap����\n");
        printf("���������ѡ��");
        int num;
        scanf("%d", &num);
        if (num == 1)
            createPcap();
        if (num == 2)
            analysisPcap();
    }

}
