/*
 * File: arp.cpp
 * Description : resolve arp packet
 * Author:  Cao Yuqin
 */
#include "global.h"

/*比较IP地址是否相同*/
bool PacketList::compare_ip(ip_address a, ip_address b)
{
    //if (a.byte1 == b.byte1 && a.byte2 == b.byte2 && a.byte3 == b.byte3 && a.byte4 == b.byte4)
    if (a.bytes[0] == b.bytes[0] && a.bytes[1] == b.bytes[1] && a.bytes[2] == b.bytes[2] && a.bytes[3] == b.bytes[3])
        return true;
    else return false;
}
/*找到tcp头部位置 返回指向tcp头部位置指针*/
tcp_header* find_tcp(packet* pack)
{
    unsigned int ip_len;
    ip_header* ip = (ip_header*)(pack->data + 14);//14为以太网头部的长度
    ip_len = (ip->ver_ihl & 0xf) * 4;
    tcp_header* th = (tcp_header*)((unsigned char*)ip + ip_len);
    return th;
}
/*计算tcp数据部分的长度*/
unsigned int len_tcp_data(packet* pack)
{
    unsigned int ip_len;
    ip_header* ip = (ip_header*)(pack->data + 14);//14为以太网头部的长度
    ip_len = (ip->ver_ihl & 0xf) * 4;
    tcp_header* th = (tcp_header*)((unsigned char*)ip + ip_len);
    unsigned int tcpdata_len = ip->tlen - ip_len - ((th->dataoffset>>4) & 0xf) * 4; //tcp数据部分长度 字节为单位
    return tcpdata_len;
}
/*找到tcp报文的数据部分 返回指向tcp报文数据位置的指针*/
unsigned char* tcp_data_set(packet* pack)
{
    unsigned char* data = (unsigned char*)pack->data;
    ip_header* ip = (ip_header*)(pack->data + 14);//14为以太网头部的长度
    unsigned long ip_len = (ip->ver_ihl & 0xf) * 4;         //ip包头长度
    tcp_header* th = (tcp_header*)((unsigned char*)ip + ip_len);//tcp头部

    data = data + 14 + ip_len + (th->dataoffset >> 4 & 0xf) * 4;    //找到tcp报文中的用户数据部分
    return data;
}
/*构造函数*/
PacketList::PacketList()
{
    currentlength = 0;
}

/*清空数据包*/
void PacketList::clear()
{
    std::vector<packet*>::iterator itr;
    for(itr = packlist.begin();itr!= packlist.end();itr++)
        delete *itr;
    packlist.clear();
    idenList.clear();
    segpack.clear();
}

/*在数据包链表中加入新的数据包 未开启ip重组功能*/
bool PacketList::add(const struct pcap_pkthdr* pkt_header, const u_char* pkt_data)
//void PacketList::add(const struct pcap_pkthdr* pkt_header, const u_char* pkt_data)
{
    packet* newpacket = new packet;
    struct tm* ltime;
    time_t local_tv_sec;

    /*捕获数据包个数加1*/
    ++currentlength;

    /*将时间转换成可识别的格式*/
    local_tv_sec = pkt_header->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime(newpacket->timestr, sizeof newpacket->timestr, "%H:%M:%S", ltime);

    newpacket->len = pkt_header->len;                          //记录捕获包的长度
    newpacket->num = currentlength;                            //记录捕获包数据编号
    newpacket->header = pkt_header; newpacket->data = pkt_data;//将所捕获包的内容复制下来,以备将来使用

    /* 获得以太网帧头部中表示类型的2字节 */
    tagDLCHeader* th;
    unsigned short type;
    th = (tagDLCHeader*)pkt_data;
    /* 将网络字节序列转换成主机字节序列 */
    th->Ethertype=ntohs(th->Ethertype);

    /*判断捕获包以太网类型*/
    type = th->Ethertype;
    if (type == 0x86dd)//IPV6
    {
        IPV6 ipv6(pkt_header, pkt_data);                //解析IPV6数据包内容
        newpacket->type ="IPV6";                        //记录数据包类型
        newpacket->message = ipv6.getmessage();         //获取数据包大概信息
        newpacket->v6saddr = ipv6.srcv6();              //获取源IPV6地址
        newpacket->v6daddr = ipv6.destv6();             //获取目的IPV6地址
        //std::cout << newpacket->num << " " << newpacket->type << " " << newpacket->message << std::endl;
    }
    if (type == 0x800)//IP
    {
        IPV4 ipv4(pkt_header, pkt_data);                //解析IPV4数据包内容
        newpacket->type = ipv4.gettype();               //进一步获取数据包类型
        newpacket->saddr = ipv4.saddr();                //获取源IP地址
        newpacket->daddr = ipv4.daddr();                //获取目的IP地址
        newpacket->message = ipv4.getmessage();         //获取数据包大概信息
        //std::cout << newpacket->num<<" "<<newpacket->type << " " << newpacket->message << std::endl;
    }
    if (type == 0x0806)//ARP
    {
        ARP arp(pkt_header, pkt_data);                  //解析ARP数据包内容
        newpacket->type = "ARP";                        //记录数据包类型
        newpacket->saddr = arp.saddr();                 //获取源IP地址
        newpacket->daddr = arp.daddr();                 //获取目的IP地址
        newpacket->message = arp.getmessage();          //获取数据包大概信息
        //std::cout << newpacket->num << " " << newpacket->type << " " << newpacket->message << std::endl;
    }
    if (type == 0x8035)//RARP
    {
        RARP rarp(pkt_header, pkt_data);                 //解析RARP数据包内容
        newpacket->type = "RARP";                        //记录数据包类型
        newpacket->saddr = rarp.saddr();                 //获取源IP地址
        newpacket->daddr = rarp.daddr();                 //获取目的IP地址
        newpacket->message = rarp.getmessage();          //获取数据包大概信息
        //std::cout << newpacket->num << " " << newpacket->type << " " << newpacket->message << std::endl;
    }
    packlist.push_back(newpacket);                       //数据包存储到容器中
    qDebug()<<"数据包个数"<<currentlength<<endl;
    return true;
}

/*在数据包链表中加入新的数据包 开启ip重组功能*/
bool PacketList::ip_add(const struct pcap_pkthdr* pkt_header, const u_char* pkt_data)
//void PacketList::ip_add(const struct pcap_pkthdr* pkt_header, const u_char* pkt_data)
{
    packet* newpacket=new packet;
    struct tm* ltime;
    time_t local_tv_sec;

    /*捕获数据包个数加1*/
    ++currentlength;

    /*将时间转换成可识别的格式*/
    local_tv_sec = pkt_header->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime(newpacket->timestr, sizeof newpacket->timestr, "%H:%M:%S", ltime);

    newpacket->len = pkt_header->len;                          //记录捕获包的长度
    newpacket->num = currentlength;                            //记录捕获包数据编号
    newpacket->header = pkt_header; newpacket->data = pkt_data;//将所捕获包的内容复制下来,以备将来使用

    /* 获得以太网帧头部中表示类型的2字节 */
    tagDLCHeader* th;
    unsigned short type;
    th = (tagDLCHeader*)pkt_data;
    /* 将网络字节序列转换成主机字节序列 */
    th->Ethertype = ntohs(th->Ethertype);
    type = th->Ethertype;

    if (type == 0x86dd)//IPV6
    {
        IPV6 ipv6(pkt_header, pkt_data);                //解析IPV6数据包内容
        newpacket->type ="IPV6";                        //记录数据包类型
        newpacket->message = ipv6.getmessage();         //获取数据包大概信息
        newpacket->v6saddr = ipv6.srcv6();              //获取源IPV6地址
        newpacket->v6daddr = ipv6.destv6();             //获取目的IPV6地址
        //qDebug() << newpacket->num << " " << newpacket->type << " " << newpacket->message << endl;
    }
    if (type == 0x800)//IPV4
    {
        IPV4 ipv4(pkt_header, pkt_data);
        if (ipv4.Issegment() )//如果是分片报文
        {
            //进行ip重组
            ip_regroup(newpacket);
            if (newpacket->num == 0)                                 //重组不完整
            {
                currentlength--;
                 //cout << newpacket->num << " " << newpacket->type << " " << newpacket->message << endl;
                return false;
            }
            //重组完整
            newpacket->message = ipv4.getmessage();         //获取数据包大概信息
            newpacket->message = newpacket->message + "[重组IPV4包]";
        }else
            newpacket->message = ipv4.getmessage();         //获取数据包大概信息
        newpacket->type = ipv4.gettype();                //进一步获取数据包类型
        newpacket->saddr = ipv4.saddr();                 //获取源IP地址
        newpacket->daddr = ipv4.daddr();                 //获取目的IP地址
    }
    if (type == 0x0806)//ARP
    {
        ARP arp(pkt_header, pkt_data);                  //解析ARP数据包内容
        newpacket->type = "ARP";                        //记录数据包类型
        newpacket->saddr = arp.saddr();                 //获取源IP地址
        newpacket->daddr = arp.daddr();                 //获取目的IP地址
        newpacket->message = arp.getmessage();          //获取数据包大概信息
        //cout << newpacket->num << " " << newpacket->type << " " << newpacket->message << endl;
    }
    if (type == 0x8035)//RARP
    {
        RARP rarp(pkt_header, pkt_data);                //解析RARP数据包内容
        newpacket->type = "RARP";                       //记录数据包类型
        newpacket->saddr = rarp.saddr();                //获取源IP地址
        newpacket->daddr = rarp.daddr();                //获取目的IP地址
        newpacket->message = rarp.getmessage();         //获取数据包大概信息
        //cout << newpacket->num << " " << newpacket->type << " " << newpacket->message << endl;
    }
    packlist.push_back(newpacket);                      //数据包存入容器
    return true;
}

/*IP重组 辅助函数*/
void bit_set(void* buf, int offset)
{
    (static_cast<char*>(buf))[offset >> 3] |= 1 << (offset & 7);
}

int bit_isset(void* buf, int offset)
{
    if ((static_cast<char*>(buf))[offset >> 3] & 1 << (offset & 7))
        return 1;
    else
        return 0;
}

/*进行ip重组函数*/
void PacketList::ip_regroup(packet* newpacket)
{
    size_t i=0;

    ip_header* ip = (ip_header*)(newpacket->data + 14);                           //14为以太网头部的长度
    unsigned short identification = ip->identification;                           //标识
    if (idenList.size() != 0)                                                     //查找是否有相同标识的报文
        for (i = 0; i < idenList.size(); ++i)
            if (idenList[i] == identification) break;

    if (i == idenList.size())													 //接收到的第一个分片 新开辟空间
    {
        idenList.push_back(identification);
        buf* buffer=new buf;
        buffer->TDL = 0;
        buffer->data = new unsigned char[8000];
        buffer->seg_PT = new unsigned char[8000];
        *(buffer->seg_PT) = 0;
        segpack.push_back(buffer);
    }

    // 拷贝数据到相应的数据缓冲中
    memcpy((segpack[i]->data) + (ip->flags_fo & 8191) * 8, newpacket->data + 14 + (ip->ver_ihl & 0xf) * 4, (ip->tlen - (ip->ver_ihl & 15) * 4));

    for (int j = (ip->flags_fo & 8191); j < ((ip->flags_fo & 8191) + ((ip->tlen - (ip->ver_ihl & 15) * 4) + 7) / 8); j++)      // 计算块位表
    {
        bit_set(segpack[i]->seg_PT, j);
    }

    if((((ip->flags_fo >> 13) & 0x1) == 0)& ((ip->flags_fo & 0x1fff) != 0))                      // 如果是最后一个分片，则计算总长度
    {
        segpack[i]->TDL = ip->tlen - ((ip->ver_ihl & 15) * 4) + (ip->flags_fo & 8191) * 8;
    }

    if((((ip->flags_fo >> 13) & 0x1) == 1)&& ((ip->flags_fo & 0x1fff) == 0))                        // 如果是第一个分片，则拷贝头部
    {
        tagDLCHeader* th= (tagDLCHeader*)newpacket->data;
        segpack[i]->ip = ip;
        segpack[i]->th = th;
    }

    if (segpack[i]->TDL != 0)                                                                          // 检查是否重组完成,下一步处理
    {
        int seg_PT_SET = 1;
        for (int j = 0; j <= ((segpack[i]->TDL + 7) / 8); j++)                                         // 重组完成 则seg_PT_SET为1
        {
            seg_PT_SET = seg_PT_SET * (bit_isset(segpack[i]->seg_PT, j));
        }
        if (seg_PT_SET)
        {
            segpack[i]->ip->tlen =(segpack[i]->TDL) + ((segpack[i]->ip->ver_ihl & 15) * 4);              //改变头部总长度
            segpack[i]->ip->flags_fo = segpack[i]->ip->flags_fo;
            segpack[i]->ip->flags_fo = segpack[i]->ip->flags_fo & 0xcfff;
            segpack[i]->ip->flags_fo = segpack[i]->ip->flags_fo | 0x4000;                               //改变头部MF和DF

            unsigned char* newdata = new unsigned char[14 + segpack[i]->ip->tlen+1];                     //拼接IP重组数据包成新的报文
            memcpy(newdata, segpack[i]->th, 14);                                                         //添加以太网头部
            memcpy(newdata + 14, segpack[i]->ip, (segpack[i]->ip->ver_ihl & 0xf) * 4);                   //添加IP头部
            //添加IP重组后的数据部分
            memcpy(newdata + 14 + (segpack[i]->ip->ver_ihl & 0xf) * 4, segpack[i]->data, segpack[i]->ip->tlen - (segpack[i]->ip->ver_ihl & 0xf) * 4);

            //存储为新的数据包
            newpacket->data = newdata;
            struct pcap_pkthdr* newheader = new struct pcap_pkthdr;
            newheader->caplen = newpacket->header->caplen;
            newheader->ts = newheader->ts;
            newheader->len= static_cast<bpf_u_int32>(14 + segpack[i]->ip->tlen);
            newpacket->header = newheader;
            newpacket->len = newheader->len;
            delete segpack[i]->data;
            delete segpack[i]->seg_PT;
            //delete segpack[i];
            segpack.erase(segpack.begin() + i);
            idenList.erase(idenList.begin() + i);
        }
        else
        {
            newpacket->num = 0;                 //表示此数据包未重组完整
        }
    }
    else
    {
        newpacket->num = 0;                     //表示此数据包未重组完整
    }
    //return newpacket;
}

/*获取存储数据包总数*/
size_t PacketList::size()
{
    return  packlist.size();
}
/*获取下标为index的数据包*/
packet* PacketList::getCont(size_t index)
{
    return packlist[index];
}
/*获取容器尾部数据包指针*/
packet* PacketList::end()
{
    return *packlist.rbegin();
}

/*tcp报文重组*/
void PacketList::tcp_regroup(size_t num, u_char *&_result, u_int &total_len)

{
    std::vector<pack_group> tmpgroup;    //方便排序 所定义的vector
    size_t mnum = num;
    packet* next;                 //所要判断是否同一文件的前一个和下一个数据包
    bool ISN_flag;                //找到初始序号
    unsigned long ISN;            //初始序号
    bool FIN_flag = false;        //找到结束序号
    bool same_flag;               //标记重复tcp报文

    /*判断重组报文是否为tcp*/
    packet* member = packlist[num];
    if (member->type != "TCP")
    {
        return ;
    }

    /*提取需重组包文的源IP 目的IP 源端口 目的端口*/
    tcp_header* member_th = find_tcp(member);
    ip_address sa = member->saddr; ip_address da = member->daddr;                 //源IP 目的IP
    unsigned short sp = member_th->sourcePort; unsigned short dp = member_th->destinationPort;//源端口 目的端口
    if (((member_th->flags >> 4) & 0x1) == 1)
    {
        /*找到isn序号*/
        ISN_flag = true;
        ISN = member_th->sequenceNumber;
    }
    else ISN_flag = false;
    if (((member_th->flags >> 5) & 0x1) == 1)
    {
        /*找到isn序号*/
        FIN_flag = true;
    }
    else FIN_flag = false;

    pack_group tmppack;
    total_len = total_len + len_tcp_data(member);
    tmppack.pack = member; tmppack.sequenceNumber = member_th->sequenceNumber;
    tmpgroup.push_back(tmppack);

    bool insert_flag;
    while (mnum != 1 && !ISN_flag)         //从当前数据包位置往前搜索
    {
        mnum--;
        next = packlist[mnum];
        if (next->type == "TCP" && compare_ip(next->saddr, sa) && compare_ip(next->daddr, da)) //判断类型 源IP地址 目的IP地址 是否相同
        {
            tcp_header* tcp_next = find_tcp(next);
            if (tcp_next->sourcePort == sp && tcp_next->destinationPort == dp)      //判断端口号是否相同
            {
                if (((tcp_next->flags >> 4) & 0x1) == 1)
                {
                    /*找到isn序号*/
                    ISN_flag = true;
                    ISN = tcp_next->sequenceNumber;
                    break;
                }
                pack_group tmppack;
                tmppack.pack = next; tmppack.sequenceNumber = tcp_next->sequenceNumber;
                insert_flag = false;
                same_flag = false;
                //将tcp数据包插入到其对应位置（排序）
                for (unsigned int i = 0; i < static_cast<unsigned int>(tmpgroup.size()); ++i)
                {
                    if (tmpgroup[static_cast<std::vector<int>::size_type>(i)].sequenceNumber == tmppack.sequenceNumber)
                    {
                        same_flag = true;
                        break;
                    }
                    if (tmpgroup[static_cast<std::vector<int>::size_type>(i)].sequenceNumber > tmppack.sequenceNumber)
                    {
                        tmpgroup.insert(tmpgroup.begin() + i, tmppack);
                        insert_flag = true;
                        break;
                    }
                }
                if (same_flag)continue;
                if (!insert_flag)tmpgroup.push_back(tmppack);
                total_len = len_tcp_data(packlist[mnum]) + total_len;
            }
        }
    }

    mnum = num;
    while (mnum != static_cast<size_t>(packlist.size()-2) && !FIN_flag)       //从当前数据包位置往后搜索
    {
        mnum++;
        next = packlist[mnum];
        if (next->type == "TCP" && compare_ip(next->saddr, sa) && compare_ip(next->daddr, da))
        {
            //判断数据包类型 源ip 目的ip是否相同
            tcp_header* tcp_next = find_tcp(next);
            if (tcp_next->sourcePort == sp && tcp_next->destinationPort == dp)
            {
                if (((tcp_next->flags >> 5) & 0x1) == 1)
                {
                    FIN_flag = true;
                    break;
                }
                pack_group tmppack;
                tmppack.pack = next; tmppack.sequenceNumber = tcp_next->sequenceNumber;
                insert_flag = false;
                same_flag = false;
                //将tcp数据包插入到其对应位置（排序）
                for (int i = static_cast<int>(tmpgroup.size() - 1); i > -1; --i)
                {
                    if (tmpgroup[static_cast<std::vector<int>::size_type>(i)].sequenceNumber == tmppack.sequenceNumber)
                    {
                        same_flag = true;
                        break;
                    }
                    if (tmpgroup[static_cast<std::vector<int>::size_type>(i)].sequenceNumber < tmppack.sequenceNumber)
                    {
                        tmpgroup.insert(tmpgroup.begin() + i + 1, tmppack);
                        insert_flag = true;
                        break;
                    }
                }
                if (same_flag) continue;
                if (!insert_flag)tmpgroup.insert(tmpgroup.begin(), tmppack);
                total_len = len_tcp_data(packlist[mnum]) + total_len;
            }
        }
    }

    /*重组tcp报文*/
    _result = new unsigned char[total_len];
    unsigned long now_len=0;
    for (size_t i = 0; i < tmpgroup.size(); ++i)
    {
        memcpy(_result + now_len, tcp_data_set(tmpgroup[i].pack), len_tcp_data(tmpgroup[i].pack));
        now_len = now_len + len_tcp_data(tmpgroup[i].pack);
    }

    return ;
}

/*查找函数*/
std::vector<int> PacketList::search(std::string keyword)
{
    unsigned short len_data;
    unsigned short ip_len;
    unsigned short ip_tlen;
    unsigned char* data;
    ip_header* ip;
    std::string message;            //所传输的用户数据
    std::string Bchar;
    size_t flag;
    std::vector<int> keypacklist;
    keypack kpt;
    for (size_t i = 1; i < packlist.size(); ++i)
    {
        if (packlist[i]->type == "TCP")
        {
            tcp_header* th;

            data = const_cast<unsigned char *>(packlist[i]->data);
            ip = (ip_header*)(packlist[i]->data + 14);//14为以太网头部的长度
            ip_len = (ip->ver_ihl & 0xf) * 4;         //ip包头长度
            ip_tlen = (ip->tlen & 0xff)* 1;           //ip包总长
            th = (tcp_header*)((unsigned char*)ip + ip_len);//tcp头部

            len_data = ip_tlen - ip_len - (th->dataoffset>>4 &0xf) * 4;     //tcp数据部分长度 字节为单位
            data = data + 14 + ip_len + (th->dataoffset >> 4 & 0xf) * 4;    //找到tcp报文中的用户数据部分

            message = "";
            for (int j = 0; j < len_data; j++)//将用户数据ascll码转换为string
            {
                unsigned char tmp;
                tmp = (*data);
                if(!isprint(tmp)) continue;
                message.push_back(static_cast<char>(tmp));
                data = data + 1;
            }
            qDebug() <<"TCP message:"<<message.c_str()<< endl;

            //在数据包部分查找关键词
            flag = message.find(keyword);
            if (flag != static_cast<size_t>(-1))//找到关键字
            {
                keypacklist.push_back(i);
            }
        }
        if (packlist[i]->type == "UDP")
        {
            data = const_cast<unsigned char*>(packlist[i]->data);
            ip = (ip_header*)(packlist[i]->data + 14);//14为以太网头部的长度
            ip_len = (ip->ver_ihl & 0xf) * 4;         //ip包头长度
            ip_tlen = (ip->tlen & 0xff) * 1;           //ip包总长
            len_data = ip_tlen - ip_len - 8; //udp数据部分长度 字节为单位

            data = data + 14 + ip_len + 8;    //找到udp报文中的用户数据部分

            message = "";
            for (int j = 0; j < len_data; j++)//将用户数据ascll码转换为string
            {
                unsigned char tmp;
                tmp = (*data);
                if(!isprint(tmp)) continue;
                data = data + 1;
            }
            qDebug() <<"UDP message:"<<message.c_str()<< endl;

            //在数据包部分查找关键词
            flag = message.find(keyword);
            if (flag != static_cast<size_t>(-1))//找到关键字
            {
                keypacklist.push_back(static_cast<int>(i));
            }
        }
    }
    return keypacklist;
}

/*获得以太网头部*/
tagDLCHeader* PacketList::getdlc(long long int num)
{
    tagDLCHeader* dh = (tagDLCHeader*)(packlist[num]->data);
    return dh;
}

/*获得arp头部*/
tagARPFrame* PacketList::getarp(long long int num)
{
    tagARPFrame* arp = (tagARPFrame*)(packlist[num]->data + 14);//14为以太网头部的长度
    return arp;
}

/*获得rarp头部*/
tagRARPFrame* PacketList::getrarp(long long int num)
{
    tagRARPFrame* rarp = (tagRARPFrame*)(packlist[num]->data + 14);//14为以太网头部的长度
    return rarp;
}

/*获得ip头部*/
ip_header* PacketList::getip(long long int num)
{
    ip_header* ip = (ip_header*)(packlist[num]->data + 14);
    return ip;
}

/*获得ipv6头部*/
ipv6_header* PacketList::getip6(long long int num)
{
    ipv6_header* ipv6 = (ipv6_header*)(packlist[num]->data+14);
    return ipv6;
}

/*获得tcp头部*/
tcp_header* PacketList::gettcp(long long int num)
{
    ip_header* ip = (ip_header*)(packlist[num]->data + 14);
    unsigned  int ip_len = (ip->ver_ihl & 0xf) * 4;
    tcp_header* th = (tcp_header*)((unsigned char*)ip + ip_len);
    return th;
}

/*获得udp头部*/
udp_header* PacketList::getudp(long long int num)
{
    ip_header* ip = (ip_header*)(packlist[num]->data + 14);
    unsigned  int ip_len = (ip->ver_ihl & 0xf) * 4;
    udp_header* uh = (udp_header*)((unsigned char*)ip + ip_len);
    return uh;
}

/*获得icmp头部*/
icmp_header* PacketList::geticmp(long long int num)
{
    ip_header* ip = (ip_header*)(packlist[num]->data + 14);
    unsigned  int ip_len = (ip->ver_ihl & 0xf) * 4;
    icmp_header* ich = (icmp_header*)((unsigned char*)ip + ip_len);
    return ich;
}

/*获得igmp头部*/
igmp_header* PacketList::getigmp(long long int num)
{
    ip_header* ip = (ip_header*)(packlist[num]->data + 14);
    unsigned  int ip_len = (ip->ver_ihl & 0xf) * 4;
    igmp_header* igh = (igmp_header*)((unsigned char*)ip + ip_len);
    return igh;
}
