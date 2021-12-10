//����STMP ����RIP
/**
* @Author xiyuan
* @Date 2021/12/5 14:14
* @Version 1.0
*/

#include <stdio.h>
#include <winsock2.h>
#include "pcap.h"

//У���
short checksum(unsigned short *buffer, int size) {
    unsigned long cksum = 0;
    while (size > 1) {
        cksum += *buffer++;
        size -= sizeof(USHORT);
    }
    if (size) {
        cksum += *(UCHAR *) buffer;
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    return ~cksum;
}

void prinfPcapFileHeader(pcap_file_header *pfh) {
    if (pfh == NULL) {
        return;
    }
    printf("=========pcap���汾��============\n"
           "magic:%0x\n"
           "version_major:%u\n"
           "version_minor:%u\n"
           "thiszone:%d\n"
           "sigfigs:%u\n"
           "snaplen:%u\n"
           "linktype:%u\n"
           "=====================\n",
           ntohl(pfh->magic),
           pfh->version_major,
           pfh->version_minor,
           pfh->thiszone,
           pfh->sigfigs,
           pfh->snaplen,
           pfh->linktype);
}

void printfPcapHeader(pcap_header *ph) {
    printf("##########    pcap����Ϣ����    ###########\n");
    if (ph == NULL) {
        return;
    }
    printf(
            "ts.timestamp_s:%u\n"
            "ts.timestamp_ms:%u\n"
            "capture_len:%u\n"
            "len:%d\n"
            "=====================\n",
            ph->ts.timestamp_s,
            ph->ts.timestamp_ms,
            ph->capture_len,
            ph->len);
}

void printPcap(void *data, size_t size) {
    unsigned short iPos = 0;
    if (data == NULL) {
        return;
    }
    printf("\n==data:0x%x,len:%lu=========", data, size);
    for (iPos = 0; iPos < size / sizeof(unsigned short); iPos++) {
        unsigned short a = ntohs(*((unsigned short *) data + iPos));
        if (iPos % 8 == 0) printf("\n");
        if (iPos % 1 == 0) printf(" ");
        printf("%04x", a);
    }
    printf("\n============\n");
}

void printfEthernetHeader(struct ethernet_header *ph) {
    printf("##########   ��·�㣨ethernet��    ###########\n");
    if (ph == NULL) {
        return;
    }

    u_char *mac_string;
    /*���MacĿ�ĵ�ַ*/
    printf("MacĿ�ĵ�ַ:\t");
    mac_string = ph->ether_dhost;
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3),
           *(mac_string + 4), *(mac_string + 5));
    /*���MacԴ��ַ*/
    printf("MacԴ��ַ:\t");
    mac_string = ph->ether_shost;
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3),
           *(mac_string + 4), *(mac_string + 5));
    printf("ether_type:%04x", ntohs(ph->ether_type));
    if (ntohs(ph->ether_type) == 0x0800)
        printf("(IPV4)");
}

struct ip_check_head ipCheckHead;//һ������������

int printfIpHeader(struct ip_header *ip_protocol) {
    if (ip_protocol == NULL) {
        return -1;
    }
    uint32_t offset = ntohs(ip_protocol->ip_off);   /*���ƫ����*/
    printf("=====================\n"
           "\n##########    ����㣨IPЭ�飩    ########### \n");
    printf("IP�汾:\t\tIPv%x\n", ip_protocol->ip_version);
    printf("IPЭ���ײ�����:\t%x\n", ip_protocol->ip_header_length);
    printf("��������:\t%x\n", ip_protocol->ip_type_service);
    printf("�ܳ���:\t\t%d\n", ntohs(ip_protocol->ip_length));/*����ܳ���*/
    printf("��ʶ:\t\t%d\n", ntohs(ip_protocol->ip_id));  /*��ñ�ʶ*/
    printf("Ƭƫ��:\t\t%d\n", (offset & 0x1fff) * 8);
    printf("����ʱ��:\t%d\n", ip_protocol->ip_ttl);     /*���ttl*/
    printf("�ײ������:\t%d\n", ntohs(ip_protocol->ip_checksum));
    u_char *mac_string;
    mac_string = ip_protocol->ip_source_address;
    printf("Դ��ַ:");
    printf("%d:%d:%d:%d\n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3)
    );
    /*���MacԴ��ַ*/
    printf("Ŀ�ĵ�ַ:");
    mac_string = ip_protocol->ip_destination_address;
    printf("%d:%d:%d:%d\n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3)
    );

    printf("Э���:\t%d\n", ip_protocol->ip_protocol);         /*���Э������*/
    printf("\n�����Э����:\t");
    switch (ip_protocol->ip_protocol) {
        case 6 :
            printf("TCP\n");
            break; /*Э��������6����TCP*/
        case 17:
            printf("UDP\n");
            break;/*17����UDP*/
        case 1:
            printf("ICMP\n");
            break;/*����ICMP*/
        case 2:
            printf("IGMP\n");
            break;/*����IGMP*/
        default :
            break;
    }
    ipCheckHead.ip_header_length = ip_protocol->ip_header_length;
    ipCheckHead.ip_version = ip_protocol->ip_version;
    ipCheckHead.ip_type_service = ip_protocol->ip_type_service;
    ipCheckHead.ip_length = ip_protocol->ip_length;
    ipCheckHead.ip_id = ip_protocol->ip_id;
    ipCheckHead.ip_off = ip_protocol->ip_off;
    ipCheckHead.ip_ttl = ip_protocol->ip_ttl;
    ipCheckHead.ip_protocol = ip_protocol->ip_protocol;
    ipCheckHead.ip_checksum = 0;
    for (int i = 0; i < 4; i++) {
        ipCheckHead.ip_source_address[i] = ip_protocol->ip_source_address[i];
        ipCheckHead.ip_destination_address[i] = ip_protocol->ip_destination_address[i];
    }
    if (checksum(&ipCheckHead, sizeof(ipCheckHead)) == ip_protocol->ip_checksum)
        printf("ip������\n");
    else
        printf("ip������\n");
    return ip_protocol->ip_protocol;
}

struct tcp_check_head printfTcpHeader(struct tcp_header *tcp_protocol) {
    struct tcp_check_head tcpCheckHead;
    u_char flags;                          /*���*/
    int header_length;                  /*ͷ����*/
    u_short windows;                /*���ڴ�С*/
    u_short urgent_pointer;     /*����ָ��*/
    u_int sequence;                 /*���к�*/
    u_int acknowledgement;   /*ȷ�Ϻ�*/
    uint16_t checksum;       /*�����*/
    uint16_t source_port;
    uint16_t destination_port;
    source_port = ntohs(tcp_protocol->tcp_source_port);
    tcpCheckHead.tcp_source_port = tcp_protocol->tcp_source_port; /*���Դ�˿ں�*/
    tcpCheckHead.tcp_destination_port = destination_port = ntohs(tcp_protocol->tcp_destination_port); /*���Ŀ�Ķ˿ں�*/
    tcpCheckHead.tcp_destination_port = tcp_protocol->tcp_destination_port;
    header_length = tcp_protocol->tcp_offset * 4;                            /*����ײ�����*/
    sequence = ntohl(tcp_protocol->tcp_acknowledgement);        /*������к�*/
    tcpCheckHead.tcp_acknowledgement = tcp_protocol->tcp_acknowledgement;
    acknowledgement = ntohl(tcp_protocol->tcp_ack);
    tcpCheckHead.tcp_ack = tcp_protocol->tcp_ack;
    tcpCheckHead.tcp_reserved = tcp_protocol->tcp_reserved;
    tcpCheckHead.tcp_offset = tcp_protocol->tcp_offset;
    windows = ntohs(tcp_protocol->tcp_windows);
    tcpCheckHead.tcp_windows = tcp_protocol->tcp_windows;
    urgent_pointer = ntohs(tcp_protocol->tcp_urgent_pointer);
    tcpCheckHead.tcp_urgent_pointer = tcp_protocol->tcp_urgent_pointer;
    tcpCheckHead.tcp_flags = flags = tcp_protocol->tcp_flags;
    checksum = ntohs(tcp_protocol->tcp_checksum);
    tcpCheckHead.tcp_checksum = checksum;
    for (int i = 0; i < 4; i++) {
        tcpCheckHead.saddr[i] = ipCheckHead.ip_source_address[i];
        tcpCheckHead.daddr[i] = ipCheckHead.ip_destination_address[i];
    }
    tcpCheckHead.zero = 0;
    tcpCheckHead.proto = 0x06;
    printf("\n==========    ����㣨TCPЭ�飩    ==========\n");
    printf("Դ�˿ڣ�\t %d\n", source_port);
    printf("Ŀ�Ķ˿ڣ�\t %d\n", destination_port);
    printf("\n���кţ�\t %u \n", sequence);
    printf("ȷ�Ϻţ�\t%u \n", acknowledgement);
    printf("�ײ����ȣ�\t%d \n", header_length);
    printf("�����ֶΣ�\t%d \n", tcp_protocol->tcp_reserved);
    printf("����λ��");
    if (flags & 0x08) printf("\t������ PSH��");
    if (flags & 0x10) printf("\t��ȷ�� ACK�� ");
    if (flags & 0x02) printf("\t��ͬ�� SYN��");
    if (flags & 0x20) printf("\t������ URG��");
    if (flags & 0x01) printf("\t����ֹ FIN��");
    if (flags & 0x04) printf("\t����λ RST��");
    printf("\n");
    printf("���ڴ�С :\t%d \n", windows);
    printf("����� :\t%x\n", checksum);
    printf("����ָ���ֶ� :\t%d\n", urgent_pointer);
    int min = (destination_port < source_port) ? destination_port : source_port;
    printf("##########    Ӧ�ò�Э��    ########### \n");
    switch (min) {
        case 80:
            printf(" http ������ά����WWW������ĳ��ı�����Э�飨HTTP��");
            break;
        case 21:
            printf(" ftp �ļ�����Э�飨FTP��");
            break;
        case 20:
            printf(" ftp ���ݣ�");
            break;
        case 143:
            printf("IMAPЭ��");
            break;
        case 23:
            printf(" telnet Telnet ����  ");
            break;
        case 25:
            printf(" smtp ���ʼ�����Э�飨SMTP��");
            break;
        case 110:
            printf(" pop3 �ʾ�Э��汾3 ");
            break;
        case 443:
            printf(" https ��ȫ���ı�����Э�飨HTTP�� ");
            break;
        case 53:
            printf(" ������DNSЭ��");
            break;
        default :
            printf("���������͡� ");
            break;
    }
    printf("\n");
    return tcpCheckHead;
}


struct check_udp_header printfUdpHeader(struct udp_header *ph) {
    struct check_udp_header checkUdpHeader;
    for (int i = 0; i < 4; i++) {
        checkUdpHeader.saddr[i] = ipCheckHead.ip_source_address[i];
        checkUdpHeader.daddr[i] = ipCheckHead.ip_destination_address[i];
    }
    checkUdpHeader.zero = 0;
    checkUdpHeader.proto = 17;
    checkUdpHeader.udp_source_port = ph->udp_source_port;
    checkUdpHeader.udp_destination_port = ph->udp_destination_port;
    checkUdpHeader.len = ph->udp_length;
    checkUdpHeader.udp_length = ph->udp_length;
    checkUdpHeader.udp_checksum = ph->udp_checksum;

    uint16_t source = ntohs(ph->udp_source_port);
    uint16_t destination = ntohs(ph->udp_destination_port);
    printf("##########   UDPЭ��    ########### \n");
    printf("Դ�˿ڣ�%d\n", destination);
    printf("Ŀ�Ķ˿ڣ�%d\n", source);
    printf("udp���ȣ�%d\n", ntohs(ph->udp_length));
    printf("У��ͣ�0x%x\n", ntohs(ph->udp_checksum));
    int min = (source < destination) ? source : destination;
    printf("##########    Ӧ�ò�Э��    ########### \n");
    switch (min) {
        case 520:
            printf(" ������RIPЭ��");
            break;
        case 123:
            printf(" ������NTPЭ��");
            break;
        case 1645:
            printf(" ������RADIUSЭ��");
            break;
        case 67:
            printf(" ������DHCPЭ��");
            break;
        case 53:
            printf(" ������DNSЭ��");
            break;
        case 161:
            printf(" ������SNMPЭ��");
            break;
        case 49:
            printf(" ������TFTPЭ��");
            break;
        default :
            printf("���������͡� ");
            break;
    }
    printf("\n");
    return checkUdpHeader;
}


//�����ļ�
void createPcapFileHeader(pcap_file_header *pfh) {
    pfh->magic = ntohl(0xd4c3b2a1);
    pfh->version_major = ntohs(0x0200);
    pfh->version_minor = ntohs(0x0400);
    pfh->thiszone = 0x0;
    pfh->sigfigs = 0x0;
    pfh->snaplen = ntohl(0x00000400);
    pfh->linktype = ntohl(0x01000000);

}

void createPcapHeader(pcap_header *ph) {
    ph->ts.timestamp_s = ntohl(0x6361a761);
    ph->ts.timestamp_ms = ntohl(0xdd870600);
    ph->capture_len = ntohl(0x75000000);
    ph->len = ntohl(0x75000000);
}


void createEthernetHeader(struct ethernet_header *ph) {
    printf("������ԭ��mac��ַ��6λ������16������ʽ�������룩\n");
    u_char *mac_string = ph->ether_dhost;
    for (int i = 0; i < 6; ++i) {
        scanf("%x", (mac_string + i));
    }
    ntohl(ph->ether_dhost);

    printf("������Ŀ��mac��ַ(6λ��)��16������ʽ�������룩\n");
    mac_string = ph->ether_shost;
    for (int i = 0; i < 6; ++i) {
        scanf("%x", (mac_string + i));
    }
    ntohl(ph->ether_shost);
    ph->ether_type = 0x0008;
}

//��������һ��ȫ�ֱ����Ա�������tcpУ����и���
struct ip_check_head ip_check_head;

void createIpHeader(struct ip_header *ph) {
    ph->ip_header_length = 5;
    ph->ip_version = 4;
    ph->ip_type_service = 0;         /*��������Differentiated Services  Field*/
    ph->ip_length = ntohs(0x67);  /*�ܳ���Total Length*/
    ph->ip_id = ntohs(0xb51b);           /*��ʶidentification*/
    ph->ip_off = ntohs(0x4000);  /*Ƭƫ��*/
    ph->ip_ttl = 0x35;            /*����ʱ��Time To Live*/
    ph->ip_protocol = 0x06;        /*Э�����ͣ�TCP����UDPЭ�飩*/
    ph->ip_checksum = 0x00;

    ip_check_head.ip_header_length = 5;
    ip_check_head.ip_version = 4;
    ip_check_head.ip_type_service = 0;
    ip_check_head.ip_length = ntohs(0x67);
    ip_check_head.ip_id = ntohs(0xb51b);
    ip_check_head.ip_off = ntohs(0x4000);
    ip_check_head.ip_ttl = 0x35;
    ip_check_head.ip_protocol = 0x06;
    ip_check_head.ip_checksum = 0x00;

//    ph->ip_checksum = ntohs(0x824F);  /*�ײ������*///33359
    printf("������ԭ��ip��ַ��4λ������10������ʽ�������룩\n");
    u_char *mac_string = ph->ip_source_address;
    for (int i = 0; i < 4; ++i) {
        scanf("%d", (mac_string + i));
        ip_check_head.ip_source_address[i] = ph->ip_source_address[i];
    }

    mac_string = ph->ip_destination_address;
    printf("������Ŀ��ip��ַ��4λ������10������ʽ�������룩\n");
    for (int i = 0; i < 4; ++i) {
        scanf("%d", (mac_string + i));
        ip_check_head.ip_destination_address[i] = ph->ip_destination_address[i];
    }
    ntohl(ip_check_head.ip_destination_address);
    ntohl(ip_check_head.ip_source_address);
    ntohl(ph->ip_destination_address);
    ntohl(ph->ip_source_address);
    printf("ip%x\n", checksum(&ip_check_head, sizeof(ip_check_head)));
    ph->ip_checksum = checksum(&ip_check_head, sizeof(ip_check_head));


}


//tcp α�ײ�+tcp�ײ�+data
void createTcpHeader(struct tcp_header *ph, int data_len, char t_data[]) {
    ph->tcp_source_port = ntohs(0x0019);          //Դ�˿ں�
    ph->tcp_destination_port = ntohs(0xfd31);    //Ŀ�Ķ˿ں�
    ph->tcp_acknowledgement = ntohl(0xb90bc349);    //���
    ph->tcp_ack = ntohl(0x278faa21);    //ȷ�Ϻ��ֶ�
    ph->tcp_reserved = 0;
    ph->tcp_offset = 5;
    ph->tcp_flags = 0x018;
    ph->tcp_windows = ntohs(0xE5);    //�����ֶ�
    ph->tcp_checksum = ntohs(0);    //�����
    ph->tcp_urgent_pointer = 0x0000;    //����ָ���ֶ�
    struct create_tcp_check_head temp1;
//α�ײ�
    for (int i = 0; i < 4; ++i) {
        temp1.saddr[i] = ip_check_head.ip_source_address[i];
        temp1.daddr[i] = ip_check_head.ip_destination_address[i];
    }
    temp1.zero = 0;
    temp1.proto = 0x06;
    temp1.len = ntohs(sizeof(struct tcp_header) + strlen(t_data));
    //tcp�ײ�
    temp1.tcp_source_port = ntohs(0x0019);
    temp1.tcp_destination_port = ntohs(0xfd31);
    temp1.tcp_acknowledgement = ntohl(0xb90bc349);
    temp1.tcp_ack = ntohl(0x278faa21);    //ȷ�Ϻ��ֶ�
    temp1.tcp_reserved = 0;
    temp1.tcp_offset = 5;
    temp1.tcp_flags = 0x018;
    temp1.tcp_windows = ntohs(0xE5);    //�����ֶ�
    temp1.tcp_checksum = ntohs(0);    //�����
    temp1.tcp_urgent_pointer = 0x0000;    //����ָ���ֶ�
    //����
    char i;
    for (i = 0; i < data_len; i++) {
        temp1.data[i] = t_data[i];
    }
    if (strlen(t_data) % 2 == 1)
        temp1.data[i] = 0;
    ph->tcp_checksum = checksum(&temp1, sizeof(temp1));
    printf("tcp%x\n", ph->tcp_checksum);
//    free(buffer);
}