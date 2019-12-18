/*
 * File: capthread.cpp
 * Description : fork thread to capture packet
 * Author:  Yang Lei
 */
#include "global.h"
// construction function
capThread::capThread(pcap_t *adhandle, pkgcount &pkgcounter, PacketList &allData, pcap_dumper_t *dumpfile):pkgcounter(pkgcounter),allData(allData)
{
    stopped = false;
    this->adhandle = adhandle;
    this->dumpfile = dumpfile;
    emit updateCount();
}
// run the thread
void capThread::run()
{
    int result;
    bool isAdd = false;
    tagDLCHeader* th;
    struct pcap_pkthdr *header;
    const u_char *pkt_data = nullptr;
    unsigned short type;
    qDebug() << "start pcap!\n";
    // wait for packet
    //pcap_dump_close(this->dumpfile);
    while(stopped != true && ((result = pcap_next_ex(adhandle, &header, &pkt_data))>=0))
    {
        // timeout
        if(result == 0)
            continue;
        //only add the pack which we can explain
        th = (tagDLCHeader*)pkt_data;
        type =ntohs(th->Ethertype);
        if(type!=0x86dd&&type!= 0x800&&type != 0x0806&&type != 0x8035)
            continue;
        u_char *data = new unsigned char [header->len];
        memcpy(data, pkt_data,header->len);
        if(type==0x800)
        {
            ip_header* ip = (ip_header*)(data + 14);
            if(ip->proto!=6&&ip->proto!=17&&ip->proto!=1&&ip->proto!=2)
                continue;
        }
        qDebug() << "get one!";
        // save the data tp temporary file
        if(dumpfile != nullptr)
            pcap_dump((u_char*)dumpfile, header, data);
        // check ipregroup status
        if(isIPgroup)
            isAdd = allData.ip_add(header, data);
        else
            isAdd = allData.add(header, data);
        // deal with ip regroup
        if(!isAdd)
            continue;
        // get the message fot display
        packet * pack= allData.getCont(allData.size()-1);
        QString timestr,saddr,daddr,type,len,message;
        timestr = pack->timestr;

        type = pack->type.c_str();
        if(type == "IPV6"){
            saddr = (pack->v6saddr.c_str());
            daddr = (pack->v6daddr.c_str());
        }else{
            saddr = (std::string(pack->saddr)).c_str();
            daddr = (std::string(pack->daddr)).c_str();
        }
        len = std::to_string(pack->len).c_str();
        message = pack->message.c_str();
        emit addOneLine(timestr, saddr,daddr,type,len,message);
        isAdd = false;
        // increase counter
        if(pack->type == std::string("ARP"))
            pkgcounter.n_arp++;
        else if(pack->type == std::string("TCP") || pack->type == std::string("HTTP"))
        {
            pkgcounter.n_tcp++;
            pkgcounter.n_ip++;
        }
        else if(pack->type == std::string("UDP"))
        {
            pkgcounter.n_udp++;
            pkgcounter.n_ip++;
        }
        else if(pack->type == std::string("ICMP"))
            pkgcounter.n_icmp++;
        else
            pkgcounter.n_other++;
        pkgcounter.n_sum++;
        pkgcounter.d_sum += pack->len;
        // update counter
        emit updateCount();

        qDebug() << pack->num << " "
                 << tr(pack->timestr) << " "
                 << tr((std::string(pack->saddr)).c_str()) << " "
                 << tr((std::string(pack->daddr)).c_str()) << " "
                 << tr(pack->type.c_str()) << " "
                 << tr(std::to_string(pack->len).c_str()) << " "
                 << tr(pack->message.c_str()) << endl;
    }
}
// stop the capture thread
void capThread::stop()
{
    QMutexLocker locker(&m_lock);
    stopped = true;
    pcap_dump_close(this->dumpfile);
    qDebug() << "thread stop";
}
