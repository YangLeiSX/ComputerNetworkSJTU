/*
 * File: arp.cpp
 * Description : resolve arp packet
 * Author:  Cao Yuqin
 */
#include "global.h"

IPV4::IPV4(const struct pcap_pkthdr* pkt_header, const unsigned char* pkt_data)
{
    header = pkt_header;
    data = pkt_data;
    ip = (ip_header*)(pkt_data + 14);//14为以太网头部的长度
    ip->tlen = ntohs(ip->tlen);
    ip->identification = ntohs(ip->identification);
    ip->crc = ntohs(ip->crc);
    ip->flags_fo = ntohs(ip->flags_fo);
    ip_len = (ip->ver_ihl & 0xf) * 4;

    //进一步细分数据包类型
    switch (ip->proto) {
    case 6:
    {	type = "TCP";
        tcp_header* th = (tcp_header*)((unsigned char*)ip + ip_len);
        //if (ntohs(th->sourcePort) == 80 || ntohs(th->destinationPort) == 80) type = "HTTP";
        break;
    }
    case 17:
        type = "UDP"; break;
    case 1:
        type = "ICMP"; break;
    case 2:
        type = "IGMP"; break;
    default:
        type = " ";
    }

}

std::string IPV4::gettype()
{
    return type;
}
ip_address IPV4::saddr()
{
    return ip->saddr;
}
ip_address IPV4::daddr()
{
    return ip->daddr;
}

/*将tcp头部转为主机顺序*/
tcp_header* IPV4::tcp()
{
    tcp_header* th= (tcp_header*)((unsigned char*)ip + ip_len);
    th->sourcePort = ntohs(th->sourcePort);
    th->destinationPort = ntohs(th->destinationPort);
    th->sequenceNumber = ntohl(th->sequenceNumber);
    th->acknowledgeNumber = ntohl(th->acknowledgeNumber);
    th->windows = ntohs(th->windows);
    th->checksum = ntohs(th->checksum);
    th->urgentPointer = ntohs(th->urgentPointer);
    return th;
}
/*将udp头部转为主机顺序*/
udp_header* IPV4::udp()
{
    udp_header* uh=(udp_header*)((unsigned char*)ip+ip_len);
    uh->sourcePort = ntohs(uh->sourcePort);
    uh->destinationPort = ntohs(uh->destinationPort);
    uh->len = ntohs(uh->len);
    uh->checksum = ntohs(uh->checksum);
    return uh;
}
/*将icmp头部转为主机顺序*/
icmp_header* IPV4::icmp()
{
    icmp_header* ich = (icmp_header*)((unsigned char*)ip + ip_len);
    ich->icmp_checksum = ntohs(ich->icmp_checksum);
    ich->icmp_id = ntohs(ich->icmp_id);
    ich->icmp_sequence = ntohs(ich->icmp_sequence);
    ich->icmp_timestamp = ntohl(ich->icmp_timestamp);
    unsigned char t = (ich->icmp_type >> 4) & 0xf;
    switch (t)
    {
    case 0:case 8:case 9:case 10:case 13:case 14:case 15:case 16:case 17:case 18:
        icmp_type = "查询报文"; break;
    case 3:case 4:case 5:case 11:case 12:
        icmp_type = "差错报文"; break;
    default: icmp_type = "";
    }
    return ich;
}
/*将igmp头部转为主机顺序*/
igmp_header* IPV4::igmp()
{
    igmp_header* igh = (igmp_header*)((unsigned char*)ip + ip_len);
    igh->uCheckSum = ntohs(igh->uCheckSum);

    unsigned char t = (igh->hVerType >> 4) & 0xf;//IGMP报文头4未版本号
    switch (t)
    {
    case 1:
        igmp_ver = "V1";
        igmp_type = "";
        if ((igh->hVerType & 0xf)== 0x11)
        {
            igmp_type = "成员关系查询报文";
            message = igmp_type;
        }
        if ((igh->hVerType & 0xf) == 0x12)
        {
            igmp_type = "成员关系报告报文";
            message = igmp_type;
        }
        break;
    case 2:
        igmp_ver = "V2";
        igmp_type = "";
        if ((igh->hVerType & 0xf )== 0x11)
        {
            igmp_type = "成员关系查询报文";
            message = igmp_type;
        }
        if ((igh->hVerType & 0xf) == 0x16)
        {
            igmp_type = "成员关系报告报文";
            message = igmp_type;
        }
        if ((igh->hVerType & 0xf) == 0x11)
        {
            igmp_type = "离开组报文";
            message = (std::string)ip->saddr + "离开" + (std::string)igh->dwGroupAddress + "组";
        }
        break;
    case 3:
        igmp_ver = "V3";
        if ((igh->hVerType & 0xf) == 0x11)
        {
            igmp_type = "成员关系查询报文";
            message = igmp_type;
        }
        if ((igh->hVerType & 0xf) == 0x22)
        {
            igmp_type = "成员关系报告报文";
            message = igmp_type;
        }
        break;
    default:
        break;
    }
    return igh;
}

/*获得数据包大概信息*/
std::string IPV4::getmessage()
{
    switch (ip->proto) {
    case 6:
    {	if (type == "HTTP") { message = ""; break; }
        tcp_header* th = tcp();
        message = "从源端口" + std::to_string(th->sourcePort) + "发送到目的端口" + std::to_string(th->destinationPort)+"[";
        unsigned char f = th->flags;
        if ((f & 0x1) == 1)message = message + " FIN";
        f = f >> 1;
        if ((f & 0x1) == 1)message = message + " SYN";
        f = f >> 1;
        if ((f & 0x1) == 1)message = message + " RST";
        f = f >> 1;
        if ((f & 0x1) == 1)message = message + " PSH";
        f = f >> 1;
        if ((f & 0x1) == 1)message = message + " ACK";
        f = f >> 1;
        if ((f & 0x1) == 1)message = message + " URG";
        message = message + " ]";
        break;
        }
    case 17:
    {
        udp_header * uh = udp();
        message = "从源端口" + std::to_string(uh->sourcePort) + "发送到目的端口" + std::to_string(uh->destinationPort);
        break;
    }
    case 1:
    {
        icmp_header* ich = icmp();
        message = icmp_type;
        break;
    }
    case 2:
    {
        igmp_header* igh = igmp();       //message在igmp成员函数中完成赋值
        break;
    }
    default:
        message = "";
    }
    return message;
}

/*判断ip数据包是否分片*/
bool IPV4::Issegment()
{
    if ((((ip->flags_fo >> 13) & 0x1) == 0)& ((ip->flags_fo & 0x1fff) == 0))//MF为0 段偏移量为0
        return false;
    else return true;
}
