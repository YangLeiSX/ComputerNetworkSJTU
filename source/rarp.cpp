/*
 * File: arp.cpp
 * Description : resolve arp packet
 * Author:  Cao Yuqin
 */
#include "global.h"

/*将MAC地址转化为string字符串*/
std::string conver_mac_addr(unsigned char addr[6])
{
    char tmp[30];
    sprintf(tmp,"%02d:%02d:%02d:%02d:%02d:%02d", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
    std::string address = tmp; //效率最高的方法
    return address;
}

RARP::RARP(const struct pcap_pkthdr* pkt_header, const unsigned char* pkt_data)
{
    header = pkt_header;
    data = pkt_data;
    rarp = (tagRARPFrame*)(pkt_data + 14);//14为以太网头部的长度
    //转为主机顺序
    rarp->HW_Type = ntohs(rarp->HW_Type);
    rarp->Prot_Type = ntohs(rarp->Prot_Type);
    rarp->Opcode = ntohs(rarp->Opcode);
}
/*获得源IP地址*/
ip_address RARP::saddr()
{
    return rarp->saddr;
}
/*获得目的IP地址*/
ip_address RARP::daddr()
{
    return rarp->daddr;
}
/*获得大概信息*/
std::string RARP::getmessage()
{
    switch (rarp->Opcode)
    {
    case 3:
        message = "MAC地址为"+conver_mac_addr(rarp->Send_HW_Addr) + "询问" + conver_mac_addr(rarp->Targ_HW_Addr) + "的IP地址";
        break;
    case 4:
        message = "MAC地址为" + conver_mac_addr(rarp->Send_HW_Addr) + "回复" + conver_mac_addr(rarp->Targ_HW_Addr) + "的IP地址";
        break;
    default:
        break;
    }
    return message;
}
