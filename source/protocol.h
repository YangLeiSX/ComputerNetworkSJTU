/*
 * File: protocol.h
 * Description : struct for all kinds of protocol
 * Author:  Cao Yuqin
 */
#ifndef PROTOCOL_H
#define PROTOCOL_H
#include <string>
#include <cstring>
typedef unsigned char u_char;

/*
 * Struct tagDLCHeader
 * Description : struct for data link layer Ethernet
 * Author:  Cao Yuqin
 */
typedef struct _tagDLCHeader
{
    unsigned char      DesMAC[6];      /* destination HW addrress */
    unsigned char      SrcMAC[6];      /* source HW addresss */
    unsigned short     Ethertype;      /* ethernet type */
} tagDLCHeader;

/*
 * Struct ip_address
 * Description : ip address format
 * Author:  Yang Lei
 */
typedef struct _ip_address    //四个字节的IP地址
{
    unsigned char bytes[4];

    operator::std::string()
    {
        std::string address;
        address = std::to_string(this->bytes[0]) + "." + std::to_string(this->bytes[1]) + "." + std::to_string(this->bytes[2]) + "." + std::to_string(this->bytes[3]);
        return address;
    }
} ip_address;
/*
 * Struct tagARPFrame
 * Description : struct for ARP Header
 * Author:  Cao Yuqin
 */
typedef struct _tagARPFrame
{
    unsigned short     HW_Type;           //16位硬件类型
    unsigned short     Prot_Type;        //16位协议类型
    unsigned char      HW_Addr_Len;     //8位硬件地址长度
    unsigned char      Prot_Addr_Len;   //8位协议地址长度
    unsigned short     Opcode;            //16位操作类型
    unsigned char      Send_HW_Addr[6]; //源MAC地址
    ip_address         saddr; //源IP地址
    unsigned char      Targ_HW_Addr[6]; //目标MAC地址（全为0）
    ip_address         daddr; //目标IP地址
    unsigned char      padding[18];
} tagARPFrame;
/*
 * Struct tagRARPHeader
 * Description : struct for RARO header
 * Author:  Cao Yuqin
 */
typedef struct _tagRARPFrame
{
    unsigned short     HW_Type;           //16位硬件类型
    unsigned short     Prot_Type;        //16位协议类型
    unsigned char      HW_Addr_Len;     //8位硬件地址长度
    unsigned char      Prot_Addr_Len;   //8位协议地址长度
    unsigned short     Opcode;            //16位操作类型
    unsigned char      Send_HW_Addr[6]; //源MAC地址
    ip_address         saddr; //源IP地址
    unsigned char      Targ_HW_Addr[6]; //目标MAC地址（全为0）
    ip_address         daddr; //目标IP地址
    unsigned char      padding[18];
} tagRARPFrame;
/*
 * Struct ip_header
 * Description : struct for IP header
 * Author:  Cao Yuqin
 */
typedef struct _ip_header//ip头部
{
    unsigned char  ver_ihl;         // 版本 (4 bits) + 首部长度 (4 bits)
    unsigned char  tos;             // 服务类型(Type of service)
    unsigned short tlen;            // 总长(Total length)
    unsigned short identification;  // 标识(Identification)
    unsigned short flags_fo;        // 标志位(Flags) (3 bits) + 段偏移量(Fragment offset) (13 bits)
    unsigned char  ttl;             // 存活时间(Time to live)
    unsigned char  proto;           // 协议(Protocol)
    unsigned short crc;             // 首部校验和(Header checksum)
    ip_address  saddr;              // 源地址(Source address)
    ip_address  daddr;              // 目的地址(Destination address)
    unsigned int   op_pad;          // 选项与填充(Option + Padding)
} ip_header;
/*
 * Struct ipv6_header
 * Description : struct for ipv6 header
 * Author:  Cao Yuqin
 */
typedef struct _ipv6_header
{
    unsigned char ver_tf;                //版本号（4 bit）
    unsigned char traffic;               //优先级（8 bit）
    unsigned short label;                //流标识（20 bit）
    unsigned char length[2];             //报文长度（16 bit）
    unsigned char next_header;           //下一头部（8 bit）
    unsigned char limits;                //跳数限制（8 bit）
    unsigned char Srcv6[16];             //源IPv6地址（128 bit）
    unsigned char Destv6[16];            //目的IPv6地址（128 bit）
} ipv6_header;
/*
 * Struct icmp_header
 * Description : struct for icmp header
 * Author:  Cao Yuqin
 */
typedef struct _icmp_header
{
    unsigned char icmp_type;            //消息类型
    unsigned char icmp_code;            //代码
    unsigned short icmp_checksum;       //校验和
    unsigned short icmp_id;             //用来惟一标识此请求的ID号，通常设置为进程ID
    unsigned short icmp_sequence;       //序列号
    unsigned long icmp_timestamp;       //时间戳
} icmp_header;
/*
 * Struct igmp_header
 * Description : struct for igmp header
 * Author:  Cao Yuqin
 */
typedef struct _igmp_header
{
    unsigned char hVerType;         //版本号和类型(各4位)
    unsigned char uReserved;        //未用
    unsigned short uCheckSum;       //校验和
    ip_address dwGroupAddress;      //32为组地址(D类IP地址)
} igmp_header;
/*
 * Struct tcp_header
 * Description : struct for tcp_header
 * Author:  Cao Yuqin
 */
typedef struct _tcp_header
{
    unsigned short sourcePort;          //16位源端口号
    unsigned short destinationPort;     //16位目的端口号
    unsigned long sequenceNumber;       //32位序列号
    unsigned long acknowledgeNumber;    //32位确认号
    unsigned char dataoffset;           //4位首部长度/6位保留字
    unsigned char flags;                //6位标志位
    unsigned short windows;             //16位窗口大小
    unsigned short checksum;            //16位校验和
    unsigned short urgentPointer;       //16位紧急数据偏移量
} tcp_header;
/*
 * Struct udp_header
 * Description : struct for udp_header
 * Author:  Cao Yuqin
 */
typedef struct _udp_header
{
    unsigned short sourcePort;          //源端口号
    unsigned short destinationPort;     //目的端口号
    unsigned short len;                 //封包长度
    unsigned short checksum;            //校验和
} udp_header;
/*
 * Struct packet
 * Description : struct for data packet and abstract
 * Author:  Cao Yuqin
 */
typedef struct _packet
{
    const struct pcap_pkthdr* header;
    const unsigned char* data;
    long long int num;              //数据包链表中第几个捕获的数据包
    char timestr[16];               //捕获到此数据包的时间
    std::string type;               //表示数据包的协议类型
    std::string message;            //数据包所携带信息概括
    ip_address  saddr;              // 源地址(Source address)
    ip_address  daddr;              // 目的地址(Destination address)
    unsigned int len;
    std::string v6saddr;
    std::string v6daddr;
} packet;
/*
 * Struct keypack
 * Description : struct for packet search
 * Author:  Cao Yuqin
 */
typedef struct _keypack
{
    packet* pack;
    std::string message;
} keypack;
#endif // PROTOCOL_H
