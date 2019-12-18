/*
 * File: arp.cpp
 * Description : resolve arp packet
 * Author:  Cao Yuqin
 */
#include"global.h"

IPV6::IPV6(const struct pcap_pkthdr* pkt_header, const unsigned char* pkt_data)
{
    header = pkt_header;
    data = pkt_data;
    message = "";
    ipv6 = (ipv6_header*)(pkt_data + 14);//14为以太网头部的长度
    ipv6->label = ntohs(ipv6->label);
}

/*将源ipv6地址转为string*/
std::string IPV6::srcv6()
{
    char tmp[72];
    sprintf(tmp, "%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X", ipv6->Srcv6[0], ipv6->Srcv6[1], ipv6->Srcv6[2],
        ipv6->Srcv6[3], ipv6->Srcv6[4], ipv6->Srcv6[5], ipv6->Srcv6[6], ipv6->Srcv6[7], ipv6->Srcv6[8], ipv6->Srcv6[9], ipv6->Srcv6[10],
        ipv6->Srcv6[11], ipv6->Srcv6[12], ipv6->Srcv6[13], ipv6->Srcv6[14], ipv6->Srcv6[15]);
    std::string address = tmp;
    return address;
}

/*将源ipv6地址转为string*/
std::string IPV6::destv6()
{
    char tmp[72];
    sprintf(tmp, "%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X", ipv6->Destv6[0], ipv6->Destv6[1], ipv6->Destv6[2],
        ipv6->Destv6[3], ipv6->Destv6[4], ipv6->Destv6[5], ipv6->Destv6[6], ipv6->Destv6[7], ipv6->Destv6[8], ipv6->Destv6[9], ipv6->Destv6[10],
        ipv6->Destv6[11], ipv6->Destv6[12], ipv6->Destv6[13], ipv6->Destv6[14], ipv6->Destv6[15]);
    std::string address = tmp;
    return address;
}

/*获得ipv6大概信息*/
std::string IPV6::getmessage()
{
    message = "从源IPV6地址" + srcv6() + "发送到目的IPV6地址" + destv6();
    return message;
}
