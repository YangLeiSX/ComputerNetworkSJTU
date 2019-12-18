/*
 * File: global.h
 * Description : global class, struct and variable definitions
 * Author:  Yang Lei
 */
#ifndef GLOBAL_H
#define GLOBAL_H
#define HAVE_REMOTE

#include <iostream>
#include <string>
#include <vector>
#include <string>
#include <cstdlib>

#include "pcap.h"
#include "Packet32.h"
#include <winsock2.h>
#include <winsock.h>

#include <QDebug>
#include <QThread>
#include <QMutex>
#include <QAction>
#include <QMenu>
#include <QtDebug>
#include <QMessageBox>
#include <QDir>
#include <QFileDialog>
#include <QCloseEvent>

#include "protocol.h"
/*
 * Class IPV4
 * Description : class for ipv4 resolve
 * Author:  Cao Yuqin
 */
class IPV4
{
private:
    ip_header *ip;
    const unsigned char* data;
    const struct pcap_pkthdr* header;
    std::string message;
    std::string type;               //数据包协议类型
    unsigned int ip_len;            //ip头部长度
    std::string icmp_type;          //icmp类型
    std::string igmp_ver;           //igmp版本
    std::string igmp_type;          //igmp类型
public:
    IPV4(const struct pcap_pkthdr* pkt_header, const unsigned char* pkt_data);
    std::string gettype();          //获取数据包类型
    ip_address saddr();             //获取源ip地址(Source address)
    ip_address daddr();             //获取目的ip地址(Destination address)
    std::string getmessage();       //分析数据包大概信息
    bool Issegment();
    tcp_header* tcp();
    udp_header* udp();
    icmp_header* icmp();
    igmp_header* igmp();
};
/*
 * Class IPV6
 * Description : class for ipv6 resolve
 * Author:  Cao Yuqin
 */
class IPV6
{
private:
    ipv6_header* ipv6;
    const unsigned char* data;
    const struct pcap_pkthdr* header;
    std::string message;
public:
    IPV6(const struct pcap_pkthdr* pkt_header, const unsigned char* pkt_data);
    std::string srcv6();            //获取源IPv6地址
    std::string destv6();           //获取目的IPv6地址
    std::string getmessage();       //分析arp数据包所携带大概信息
};
/*
 * Class: ARP
 * Description : class for arp resolve
 * Author:  Cao Yuqin
 */
class ARP
{
private:
    tagARPFrame* arp;
    const unsigned char* data;
    const struct pcap_pkthdr* header;
    std::string message;
public:
    ARP(const struct pcap_pkthdr* pkt_header, const unsigned char* pkt_data);
    ip_address saddr();             //获取源ip地址(Source address)
    ip_address daddr();             //获取目的ip地址(Destination address)
    std::string getmessage();       //分析arp数据包所携带大概信息
};
/*
 * Class RARP
 * Description : class for rarp resolve
 * Author:  Cao Yuqin
 */
class RARP
{
private:
    tagRARPFrame* rarp;             //rarp头部
    const unsigned char* data;
    const struct pcap_pkthdr* header;
    std::string message;            //rarp所包含大概内容
public:
    RARP(const struct pcap_pkthdr* pkt_header, const unsigned char* pkt_data);
    ip_address saddr();             //获取源ip地址(Source address)
    ip_address daddr();             //获取目的ip地址(Destination address)
    std::string getmessage();       //分析rarp数据包所携带大概信息
};
/*
 * Struct pkgcount
 * Description : struct for packet counter
 * Author:  Yang Lei
 */
typedef struct _pkgcount{
    int n_tcp;
    int n_udp;
    int n_ip;
    int n_icmp;
    int n_arp;
    int n_other;
    int n_sum;  // 总包数
    int d_sum;  // 总数据量
}pkgcount;
/*
 * Struct buf
 * Description : struct for ip regroup
 * Author:  Cao Yuqin
 */
typedef struct _buf
{
    unsigned char* data;                                // 数据缓冲
    struct pcap_pkthdr* header;
    tagDLCHeader* th;                            //以太网头部
    ip_header* ip;								// 头部缓冲
    unsigned char* seg_PT;                      // 分片块位表
    unsigned short TDL;                          // 总数据长度头部
}buf;
/*
 * Struct pack_group
 * Description : struct for ip regroup
 * Author:  Cao Yuqin
 */
typedef struct _pack_group
{
    packet* pack;
    unsigned short fragment_offset; //ip头部段偏移量
    unsigned long sequenceNumber;
}pack_group;
/*
 * Struct regrouped_data
 * Description : struct for tcp regroup
 * Author:  Yang Lei
 */
typedef struct _regrouped_data
{
    u_char * data;
    u_int   total_len;
} regrouped_data;
/*
 * Class PacjetList
 * Description : class for packet data and abstract
 * Author:  Cao Yuqin
 */
class PacketList
{
private:
    int currentlength;                      //表长
    std::vector<packet *> packlist;         //存储捕获到的数据包
    std::vector<unsigned short> idenList;   //待重组标识
    std::vector<buf*> segpack;

    // 辅助函数
    bool compare_ip(ip_address a, ip_address b);
    unsigned long tcpdata_len(unsigned short ip_tlen, unsigned char ip_ih1,tcp_header* th);

public:

    PacketList();
    ~PacketList() { clear();}
    packet *getCont(size_t index);
    packet* end();
    size_t size();
    void clear();                           //清空数据包链表
    bool add(const struct pcap_pkthdr* pkt_header, const u_char* pkt_data);
    bool ip_add(const struct pcap_pkthdr* pkt_header, const u_char* pkt_data);
    std::vector<int> search(std::string keyword);
    void ip_regroup(packet* newpacket);
    void tcp_regroup(size_t num, u_char *&data, u_int &total_len);
    // 读取详细信息
    tagDLCHeader* getdlc(long long int num);
    tagARPFrame* getarp(long long int num);
    tagRARPFrame* getrarp(long long int num);
    ip_header* getip(long long int num);
    ipv6_header* getip6(long long int num);
    tcp_header* gettcp(long long int num);
    udp_header* getudp(long long int num);
    icmp_header* geticmp(long long int num);
    igmp_header* getigmp(long long int num);
};
/*
 * Class capThread
 * Description : new thread for packet capture
 * Author:  Yang Lei
 */
class capThread:public QThread
{
    Q_OBJECT
public:
   capThread(pcap_t *adhandle, pkgcount &pkgcounter, PacketList &allData, pcap_dumper_t *dumpfile);
    void stop();
protected:
    void run();
private:
    QMutex m_lock;
    volatile bool stopped;
    pcap_t *adhandle;
    pkgcount &pkgcounter;
    PacketList &allData;
    pcap_dumper_t *dumpfile;
signals:
    void addOneLine(QString timestr, QString srcIP, QString dstIP, QString proto, QString length, QString summarize);
    void updateCount();
};

// global avriables
// get device list
extern int devCount;
extern int selectDev;
extern pcap_if_t* allDevs;
extern pcap_if_t* d;
// pcap handle
extern pcap_t* adhandle;
extern capThread* capthread;
// temporary file
extern pcap_dumper_t* dumpfile;
// pcap errbuf
extern char errbuf[PCAP_ERRBUF_SIZE+1];
// filter rule
extern char* filter;
// captured packet
extern pkgcount pkgcounter;
extern PacketList allData;
extern std::vector<int> selectedData;
extern std::string keyword;
extern int selected;
extern bool isIPgroup;
extern regrouped_data tcp_regrouped;

#endif // GLOBAL_H
