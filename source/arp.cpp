/*
 * File: arp.cpp
 * Description : resolve arp packet
 * Author:  Cao Yuqin
 */
#include "global.h"

ARP::ARP(const struct pcap_pkthdr* pkt_header, const unsigned char* pkt_data)
{
    header = pkt_header;
    data = pkt_data;
    message = "";
    arp = (tagARPFrame*)(pkt_data + 14);//14为以太网头部的长度
    //转为主机顺序
    arp->HW_Type = ntohs(arp->HW_Type);
    arp->Prot_Type = ntohs(arp->Prot_Type);
    arp->Opcode = ntohs(arp->Opcode);
}
/*获得源IP地址*/
ip_address ARP::saddr()
{
    return arp->saddr;
}
/*获得目的IP地址*/
ip_address ARP::daddr()
{
    return arp->daddr;
}
/*获得大概信息*/
std::string ARP::getmessage()
{
    switch (arp->Opcode)
    {
    case 1:
        message = std::string(arp->saddr) + "询问" + std::string(arp->daddr) + "的MAC地址";
        break;
    case 2:
        message = std::string(arp->saddr) + "向" + std::string(arp->daddr) + "回复询问";
        break;
    default:
        break;
    }
    return message;
}
