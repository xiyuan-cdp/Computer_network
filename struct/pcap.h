/**
* @Author xiyuan
* @Date 2021/12/5 14:14
* @Version 1.0
*/

#ifndef pcaptest_pcap_h
#define pcaptest_pcap_h


typedef unsigned int uint32_t;
typedef unsigned short u_short;
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef int bpf_int32;
/*
 Pcap文件头24B各字段说明：
 Magic：4B：0x1A 2B 3C 4D:用来标示文件的开始
 Major：2B，0x02 00:当前文件主要的版本号     
 Minor：2B，0x04 00当前文件次要的版本号
 ThisZone：4B当地的标准时间；全零
 SigFigs：4B时间戳的精度；全零
 SnapLen：4B最大的存储长度    
 LinkType：4B链路类型
 常用类型：
 0            BSD loopback devices, except for later OpenBSD
 1            Ethernet, and Linux loopback devices
 6            802.5 Token Ring
 7            ARCnet
 8            SLIP
 9            PPP
 */

typedef struct pcap_file_header {
    uint32_t magic;
    u_short version_major;
    u_short version_minor;
    bpf_int32 thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t linktype;
} pcap_file_header;

/*
 Packet包头和Packet数据组成
 字段说明：
 Timestamp：时间戳高位，精确到seconds     
 Timestamp：时间戳低位，精确到microseconds
 Caplen：当前数据区的长度，即抓取到的数据帧长度，由此可以得到下一个数据帧的位置。
 Len：离线数据长度：网络中实际数据帧的长度，一般不大于caplen，多数情况下和Caplen数值相等。
 Packet数据：即 Packet（通常就是链路层的数据帧）具体内容，长度就是Caplen，这个长度的后面，就是当前PCAP文件中存放的下一个Packet数据包，也就 是说：PCAP文件里面并没有规定捕获的Packet数据包之间有什么间隔字符串，下一组数据在文件中的起始位置。我们需要靠第一个Packet包确定。
 */

typedef struct timestamp {
    uint32_t timestamp_s;
    uint32_t timestamp_ms;
} timestamp;

typedef struct pcap_header {
    timestamp ts;
    uint32_t capture_len;
    uint32_t len;//文本长度

} pcap_header;
struct ethernet_header {
    uint8_t ether_dhost[6];/*目的以太地址*/
    uint8_t ether_shost[6];  /*源以太网地址*/
    uint16_t ether_type;       /*以太网类型*///802.11
} ethernet_header;


struct ip_header {
#ifdef WORKS_BIGENDIAN
    u_int8_t ip_version:4,    /*version:4*/
       ip_header_length:4; /*IP协议首部长度Header Length*/
#else
    uint8_t ip_header_length: 4,
            ip_version: 4;
#endif

    uint8_t ip_type_service;         /*服务类型Differentiated Services  Field*/
    uint16_t ip_length;  /*总长度Total Length*/
    uint16_t ip_id;           /*标识identification*/
    uint16_t ip_off;  /*片偏移*/
    uint8_t ip_ttl;            /*生存时间Time To Live*/
    uint8_t ip_protocol;        /*协议类型（TCP或者UDP协议）*/
    uint16_t ip_checksum;  /*首部检验和*/
    char ip_source_address[4]; /*源IP*/
    char ip_destination_address[4]; /*目的IP*/
} ipHeader;
struct tcp_header {
    uint16_t tcp_source_port;          //源端口号

    uint16_t tcp_destination_port;    //目的端口号

    uint32_t tcp_acknowledgement;    //序号

    uint32_t tcp_ack;    //确认号字段
#ifdef WORDS_BIGENDIAN
    u_int8_t tcp_offset:4 ,
     tcp_reserved:4;
#else
    uint8_t tcp_reserved: 4,
            tcp_offset: 4;
#endif
    uint8_t tcp_flags;
    uint16_t tcp_windows;    //窗口字段
    uint16_t tcp_checksum;    //检验和
    uint16_t tcp_urgent_pointer;    //紧急指针字段
} tcpHeader;
struct udp_header {
    uint16_t udp_source_port;//端口号
    uint16_t udp_destination_port;//目的端口
    uint16_t udp_length;//udp长度
    uint16_t udp_checksum;//udp校验和;
} udpHeader;
struct ip_check_head {
    uint8_t ip_header_length: 4,
            ip_version: 4;
    uint8_t ip_type_service;         /*服务类型Differentiated Services  Field*/
    uint16_t ip_length;  /*总长度Total Length*/
    uint16_t ip_id;           /*标识identification*/
    uint16_t ip_off;  /*片偏移*/
    uint8_t ip_ttl;            /*生存时间Time To Live*/
    uint8_t ip_protocol;        /*协议类型（TCP或者UDP协议）*/
    uint16_t ip_checksum;  /*首部检验和*/
    char ip_source_address[4]; /*源IP*/
    char ip_destination_address[4]; /*目的IP*/
} temp1;
struct create_tcp_check_head {
    //伪首部
    char saddr[4];      //源IP地址
    char daddr[4];      //目的IP地址
    char zero;       //置空(0)
    char proto;     //协议类型
    unsigned short len;    //TCP/UDP数据包的长度（即从TCP/UDP报头算起到数据包结束的长度，单位：字节）
//    tcp首部
    uint16_t tcp_source_port;          //源端口号
    uint16_t tcp_destination_port;    //目的端口号
    uint32_t tcp_acknowledgement;    //序号
    uint32_t tcp_ack;    //确认号字段
    uint8_t tcp_reserved: 4,
            tcp_offset: 4;
    uint8_t tcp_flags;
    uint16_t tcp_windows;    //窗口字段
    uint16_t tcp_checksum;    //检验和
    uint16_t tcp_urgent_pointer;    //紧急指针字段
//    data数据
    char data[63];
};
struct tcp_check_head {
    //伪首部
    char saddr[4];      //源IP地址
    char daddr[4];      //目的IP地址
    char zero;       //置空(0)
    char proto;     //协议类型
    unsigned short len;    //TCP/UDP数据包的长度（即从TCP/UDP报头算起到数据包结束的长度，单位：字节）
//    tcp首部
    uint16_t tcp_source_port;          //源端口号
    uint16_t tcp_destination_port;    //目的端口号
    uint32_t tcp_acknowledgement;    //序号
    uint32_t tcp_ack;    //确认号字段
    uint8_t tcp_reserved: 4,
            tcp_offset: 4;
    uint8_t tcp_flags;
    uint16_t tcp_windows;    //窗口字段
    uint16_t tcp_checksum;    //检验和
    uint16_t tcp_urgent_pointer;
//    char data[];
};
struct check_udp_header {
    char saddr[4];      //源IP地址
    char daddr[4];      //目的IP地址
    char zero;       //置空(0)
    char proto;     //协议类型
    unsigned short len;    //TCP/UDP数据包的长度（即从TCP/UDP报头算起到数据包结束的长度，单位：字节）
    uint16_t udp_source_port;//端口号
    uint16_t udp_destination_port;//目的端口
    uint16_t udp_length;//udp长度
    uint16_t udp_checksum;//udp校验和;
} ;
    //解析文件
void prinfPcapFileHeader(pcap_file_header *pfh);

void printfPcapHeader(pcap_header *ph);

void printPcap(void *data, size_t size);

void printfEthernetHeader(struct ethernet_header *ph);

int printfIpHeader(struct ip_header *ph);

struct tcp_check_head printfTcpHeader(struct tcp_header *ph);

struct check_udp_header printfUdpHeader(struct udp_header *ph);

short checksum(unsigned short *buffer, int size);



//生成文件

void createPcapFileHeader(pcap_file_header *pfh);

void createPcapHeader(pcap_header *ph);

void createEthernetHeader(struct ethernet_header *ph);

void createIpHeader(struct ip_header *ph);

void createTcpHeader(struct tcp_header *ph, int data_len, char t_data[]);


#endif