/*
 * File: dialog.cpp
 * Description : display the search result
 * Author:  Yang Lei
 */
#include "dialog.h"
#include "ui_dialog.h"
#include "global.h"

// construction function
Dialog::Dialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Dialog)
{
    ui->setupUi(this);
    // setup the window
    this->setWindowTitle("Search Result");
    this->setMinimumSize(1200,900);
    this->minimumSize();
    // setup display part
    ui->tableData->setColumnCount(7);
    ui->tableData->setHorizontalHeaderLabels(QStringList() << tr("序号") << tr("时间")
                                             << tr("源IP") << tr("目标IP")
                                              << tr("协议") << tr("长度") << tr("内容"));
    ui->tableData->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tableData->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->tableData->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->tableData->setColumnWidth(0, 60);
    ui->tableData->setColumnWidth(1, 180);
    ui->tableData->setColumnWidth(2, 180);
    ui->tableData->setColumnWidth(3, 180);
    ui->tableData->setColumnWidth(4, 180);
    ui->tableData->setColumnWidth(5, 60);
    ui->tableData->setColumnWidth(6, 640);
    connect(ui->tableData, SIGNAL(cellClicked(int,int)), this, SLOT(showDetail(int, int)));
    ui->tableData->verticalHeader()->setVisible(false);
    RowCount = 0;
    ui->message->setText(tr(keyword.c_str()));
    ui->message->setReadOnly(true);
    ui->sum->setText("Found    packets!");
    display();
}

Dialog::~Dialog()
{
    delete ui;
    selectedData.clear();
}
// display the result
void Dialog::display()
{
    ui->hexData->clear();
    std::vector<int>::iterator itr;
    // traverse the data
    for(itr = selectedData.begin();itr != selectedData.end();itr++)
    {
        packet* target = allData.getCont(static_cast<size_t>(*itr));
        RowCount = ui->tableData->rowCount();
        ui->tableData->insertRow(RowCount);
        QString orderNum = QString::number(RowCount+1, 10);
        ui->tableData->setItem(RowCount, 0, new QTableWidgetItem(orderNum));
        ui->tableData->setItem(RowCount, 1, new QTableWidgetItem(target->timestr));
        ui->tableData->setItem(RowCount, 2, new QTableWidgetItem((std::string(target->saddr)).c_str()));
        ui->tableData->setItem(RowCount, 3, new QTableWidgetItem((std::string(target->daddr)).c_str()));
        ui->tableData->setItem(RowCount, 4, new QTableWidgetItem(tr(target->type.c_str())));
        ui->tableData->setItem(RowCount, 5, new QTableWidgetItem(QString::number(target->len)));
        ui->tableData->setItem(RowCount, 6, new QTableWidgetItem(tr(target->message.c_str())));
        qDebug() << "row count is" << RowCount << endl;
        if(RowCount > 1)
        {
            ui->tableData->scrollToItem(ui->tableData->item(RowCount, 0), QAbstractItemView::PositionAtBottom);
        }
        // set the color
        QColor color;
        if(target->type == "TCP" || target->type == "HTTP" ){
            color = QColor(228,255,199);
        }
        else if(target->type == "IPV6"){
            color = QColor(255,255,255);
        }
        else if(target->type == "UDP"){
            color = QColor(218,238,255);
        }
        else if(target->type == "ARP" || target->type == "RARP"){
            color = QColor(250,240,215);
        }
        else if(target->type == "ICMP" || target->type == "IGMP"){
            color = QColor(252,224,255);
        }
        for(int i = 0; i < 7 ; i ++){
            ui->tableData->item(RowCount,i)->setBackgroundColor(color);
        }
    }
    // display summarize
    QString sum_t = "Found " + QString::number(ui->tableData->rowCount()) + " packets!";
    ui->sum->setText(sum_t);
}
// display the detail
void Dialog::showDetail(int row, int column)
{
    qDebug() << row << " " << column << endl;
    ui->hexData->clear();
    ui->detailPart->clear();
    // get the data
    row = selectedData[static_cast<size_t>(row)];
    showHexData(row);

    // get the data
    packet *target = allData.getCont((size_t)row);

    QString entry;
    char buf[100];

    sprintf(buf, "Selected Packet is No.%d", row+1);
    entry = QString(buf);
    QTreeWidgetItem *root = new QTreeWidgetItem(ui->detailPart);
    root->setText(0, entry);

    //DLC frame
    entry = QString("Data Link Header");
    QTreeWidgetItem *level1 = new QTreeWidgetItem(root);
    level1->setText(0, entry);

    sprintf(buf, "%02x-%02x-%02x-%02x-%02x-%02x", allData.getdlc(row)->SrcMAC[0],allData.getdlc(row)->SrcMAC[1],
            allData.getdlc(row)->SrcMAC[2],allData.getdlc(row)->SrcMAC[3],allData.getdlc(row)->SrcMAC[4],allData.getdlc(row)->SrcMAC[5]);
    entry = "source MAC address: " + QString(buf);
    QTreeWidgetItem *srcEtherMac = new QTreeWidgetItem(level1);
    srcEtherMac->setText(0, entry);

    sprintf(buf, "%02x-%02x-%02x-%02x-%02x-%02x", allData.getdlc(row)->DesMAC[0], allData.getdlc(row)->DesMAC[1],
            allData.getdlc(row)->DesMAC[2], allData.getdlc(row)->DesMAC[3], allData.getdlc(row)->DesMAC[4], allData.getdlc(row)->DesMAC[5]);
    entry = "destination MAC address: " + QString(buf);
    QTreeWidgetItem *destEtherMac = new QTreeWidgetItem(level1);
    destEtherMac->setText(0, entry);

    sprintf(buf, "%04x", allData.getdlc(row)->Ethertype);
    entry = "type:0x" + QString(buf);
    QTreeWidgetItem *etherType = new QTreeWidgetItem(level1);
    etherType->setText(0, entry);

    // IP and ARP
    if(target->type == "ARP")
    {
        //添加ARP协议头
        entry = QString("ARP Header");
        QTreeWidgetItem *level2 = new QTreeWidgetItem(root);
        level2->setText(0, entry);

        sprintf(buf, "HardWare Type: 0x%04x", allData.getarp(row)->HW_Type);
        entry = QString(buf);
        QTreeWidgetItem *arpHtype = new QTreeWidgetItem(level2);
        arpHtype->setText(0, entry);

        sprintf(buf, "Protocol Type: 0x%04x", allData.getarp(row)->Prot_Type);
        entry = QString(buf);
        QTreeWidgetItem *arpPrtype = new QTreeWidgetItem(level2);
        arpPrtype->setText(0, entry);

        sprintf(buf, "HardWare Address Length: %d", allData.getarp(row)->HW_Addr_Len);
        entry = QString(buf);
        QTreeWidgetItem *arpHsize = new QTreeWidgetItem(level2);
        arpHsize->setText(0, entry);

        sprintf(buf, "Protocol Address Length: %d", allData.getarp(row)->Prot_Addr_Len);
        entry = QString(buf);
        QTreeWidgetItem *arpPrsize = new QTreeWidgetItem(level2);
        arpPrsize->setText(0, entry);

        sprintf(buf, "Operation Code: %d", allData.getarp(row)->Opcode);
        entry = QString(buf);
        QTreeWidgetItem *arpCode = new QTreeWidgetItem(level2);
        arpCode->setText(0, entry);

        sprintf(buf, "%02x-%02x-%02x-%02x-%02x-%02x", allData.getarp(row)->Send_HW_Addr[0], allData.getarp(row)->Send_HW_Addr[1],
                allData.getarp(row)->Send_HW_Addr[2], allData.getarp(row)->Send_HW_Addr[3], allData.getarp(row)->Send_HW_Addr[4], allData.getarp(row)->Send_HW_Addr[5]);
        entry = "Source MAC: " + QString(buf);
        QTreeWidgetItem *srcArpMac = new QTreeWidgetItem(level2);
        srcArpMac->setText(0, entry);

        sprintf(buf, "%s", (std::string(allData.getarp(row)->saddr)).c_str());
        entry = "Source IP: " + QString(buf);
        QTreeWidgetItem *srcArpIp = new QTreeWidgetItem(level2);
        srcArpIp->setText(0, entry);

        sprintf(buf, "%02x-%02x-%02x-%02x-%02x-%02x", allData.getarp(row)->Targ_HW_Addr[0], allData.getarp(row)->Targ_HW_Addr[1],
                allData.getarp(row)->Targ_HW_Addr[2], allData.getarp(row)->Targ_HW_Addr[3], allData.getarp(row)->Targ_HW_Addr[4], allData.getarp(row)->Targ_HW_Addr[5]);
        entry = "Destination MAC: " + QString(buf);
        QTreeWidgetItem *destArpMac = new QTreeWidgetItem(level2);
        destArpMac->setText(0, entry);

        sprintf(buf, "%s",(std::string(allData.getarp(row)->daddr)).c_str());
        entry = "Destination IP: " + QString(buf);
        QTreeWidgetItem *destArpIp = new QTreeWidgetItem(level2);
        destArpIp->setText(0, entry);

    }
    else if(target->type == "RARP")
    {
        //添加RARP协议头
        entry = QString("RARP Header");
        QTreeWidgetItem *level2 = new QTreeWidgetItem(root);
        level2->setText(0, entry);

        sprintf(buf, "HardWare Type: 0x%04x", allData.getrarp(row)->HW_Type);
        entry = QString(buf);
        QTreeWidgetItem *arpHtype = new QTreeWidgetItem(level2);
        arpHtype->setText(0, entry);

        sprintf(buf, "Protocol Type: 0x%04x", allData.getrarp(row)->Prot_Type);
        entry = QString(buf);
        QTreeWidgetItem *arpPrtype = new QTreeWidgetItem(level2);
        arpPrtype->setText(0, entry);

        sprintf(buf, "HardWare Address Length: %d", allData.getrarp(row)->HW_Addr_Len);
        entry = QString(buf);
        QTreeWidgetItem *arpHsize = new QTreeWidgetItem(level2);
        arpHsize->setText(0, entry);

        sprintf(buf, "Protocol Address Length: %d", allData.getrarp(row)->Prot_Addr_Len);
        entry = QString(buf);
        QTreeWidgetItem *arpPrsize = new QTreeWidgetItem(level2);
        arpPrsize->setText(0, entry);

        sprintf(buf, "Operation Code: %d", allData.getrarp(row)->Opcode);
        entry = QString(buf);
        QTreeWidgetItem *arpCode = new QTreeWidgetItem(level2);
        arpCode->setText(0, entry);

        sprintf(buf, "%02x-%02x-%02x-%02x-%02x-%02x", allData.getrarp(row)->Send_HW_Addr[0], allData.getrarp(row)->Send_HW_Addr[1],
                allData.getrarp(row)->Send_HW_Addr[2], allData.getrarp(row)->Send_HW_Addr[3], allData.getrarp(row)->Send_HW_Addr[4], allData.getrarp(row)->Send_HW_Addr[5]);
        entry = "Source MAC: " + QString(buf);
        QTreeWidgetItem *srcArpMac = new QTreeWidgetItem(level2);
        srcArpMac->setText(0, entry);

        sprintf(buf, "%s", (std::string(allData.getrarp(row)->saddr)).c_str());
        entry = "Source IP: " + QString(buf);
        QTreeWidgetItem *srcArpIp = new QTreeWidgetItem(level2);
        srcArpIp->setText(0, entry);

        sprintf(buf, "%02x-%02x-%02x-%02x-%02x-%02x", allData.getrarp(row)->Targ_HW_Addr[0], allData.getrarp(row)->Targ_HW_Addr[1],
                allData.getrarp(row)->Targ_HW_Addr[2], allData.getrarp(row)->Targ_HW_Addr[3], allData.getrarp(row)->Targ_HW_Addr[4], allData.getrarp(row)->Targ_HW_Addr[5]);
        entry = "Destination MAC: " + QString(buf);
        QTreeWidgetItem *destArpMac = new QTreeWidgetItem(level2);
        destArpMac->setText(0, entry);

        sprintf(buf, "%s",(std::string(allData.getrarp(row)->daddr)).c_str());
        entry = "Destination IP: " + QString(buf);
        QTreeWidgetItem *destArpIp = new QTreeWidgetItem(level2);
        destArpIp->setText(0, entry);
    }
    else if(target->type == "IPV6")
    {
        //添加IP协议头
        entry = QString("IPV6 Header");
        QTreeWidgetItem *level3 = new QTreeWidgetItem(root);
        level3->setText(0, entry);

        sprintf(buf, "Version : %d", 6);
        entry = QString(buf);
        QTreeWidgetItem *ipVersion = new QTreeWidgetItem(level3);
        ipVersion->setText(0, entry);

        sprintf(buf, "Priority Level: %d", allData.getip6(row)->traffic);
        entry = QString(buf);
        QTreeWidgetItem *ipHeaderLen = new QTreeWidgetItem(level3);
        ipHeaderLen->setText(0, entry);

        sprintf(buf, "Flow Label: %d", allData.getip6(row)->label);
        entry = QString(buf);
        QTreeWidgetItem *ipTos = new QTreeWidgetItem(level3);
        ipTos->setText(0, entry);

        sprintf(buf, "Total Length: %s", allData.getip6(row)->length);
        entry = QString(buf);
        QTreeWidgetItem *ipTotalLen = new QTreeWidgetItem(level3);
        ipTotalLen->setText(0, entry);

        sprintf(buf, "Next Header: %s", allData.getip6(row)->next_header);
        entry = QString(buf);
        QTreeWidgetItem *ipIdentify = new QTreeWidgetItem(level3);
        ipIdentify->setText(0, entry);

        sprintf(buf, "Hop Limits: %d", allData.getip6(row)->limits);
        entry = QString(buf);
        QTreeWidgetItem *flag0 = new QTreeWidgetItem(level3);
        flag0->setText(0, entry);

        sprintf(buf, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                allData.getip6(row)->Srcv6[0],allData.getip6(row)->Srcv6[1],allData.getip6(row)->Srcv6[2],allData.getip6(row)->Srcv6[3],
                allData.getip6(row)->Srcv6[4],allData.getip6(row)->Srcv6[5],allData.getip6(row)->Srcv6[6],allData.getip6(row)->Srcv6[7],
                allData.getip6(row)->Srcv6[8],allData.getip6(row)->Srcv6[9],allData.getip6(row)->Srcv6[10],allData.getip6(row)->Srcv6[11],
                allData.getip6(row)->Srcv6[12],allData.getip6(row)->Srcv6[13],allData.getip6(row)->Srcv6[14],allData.getip6(row)->Srcv6[15]);
        entry = "Source IP: " + QString(buf);
        QTreeWidgetItem *ipSrcIp = new QTreeWidgetItem(level3);
        ipSrcIp->setText(0, entry);

        sprintf(buf, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                allData.getip6(row)->Destv6[0],allData.getip6(row)->Destv6[1],allData.getip6(row)->Destv6[2],allData.getip6(row)->Destv6[3],
                allData.getip6(row)->Destv6[4],allData.getip6(row)->Destv6[5],allData.getip6(row)->Destv6[6],allData.getip6(row)->Destv6[7],
                allData.getip6(row)->Destv6[8],allData.getip6(row)->Destv6[9],allData.getip6(row)->Destv6[10],allData.getip6(row)->Destv6[11],
                allData.getip6(row)->Destv6[12],allData.getip6(row)->Destv6[13],allData.getip6(row)->Destv6[14],allData.getip6(row)->Destv6[15]);
        entry = "Destination IP: " + QString(buf);
        QTreeWidgetItem *ipDestIp = new QTreeWidgetItem(level3);
        ipDestIp->setText(0, entry);

    }
    else if(target->type == "IP" || target->type == "TCP" || target->type == "UDP"
            || target->type == "ICMP" || target->type == "IGMP" || target->type == "HTTP")
    {
        //添加IP协议头
        entry = QString("IP Header");
        QTreeWidgetItem *level3 = new QTreeWidgetItem(root);
        level3->setText(0, entry);

        sprintf(buf, "Version : %d", (allData.getip(row)->ver_ihl & 0xf0) >> 4);
        entry = QString(buf);
        QTreeWidgetItem *ipVersion = new QTreeWidgetItem(level3);
        ipVersion->setText(0, entry);

        sprintf(buf, "IP header length: %d", allData.getip(row)->ver_ihl & 0x0f);
        entry = QString(buf);
        QTreeWidgetItem *ipHeaderLen = new QTreeWidgetItem(level3);
        ipHeaderLen->setText(0, entry);

        sprintf(buf, "Serivce Type: %d", allData.getip(row)->tos);
        entry = QString(buf);
        QTreeWidgetItem *ipTos = new QTreeWidgetItem(level3);
        ipTos->setText(0, entry);

        sprintf(buf, "Total Length: %d", allData.getip(row)->tlen);
        entry = QString(buf);
        QTreeWidgetItem *ipTotalLen = new QTreeWidgetItem(level3);
        ipTotalLen->setText(0, entry);

        sprintf(buf, "Identification: 0x%04x", allData.getip(row)->identification);
        entry = QString(buf);
        QTreeWidgetItem *ipIdentify = new QTreeWidgetItem(level3);
        ipIdentify->setText(0, entry);

        sprintf(buf, "Reserved Fragment Flag: %d", (allData.getip(row)->flags_fo & 0x8000) >> 15);
        entry = QString(buf);
        QTreeWidgetItem *flag0 = new QTreeWidgetItem(level3);
        flag0->setText(0, entry);

        sprintf(buf, "Don't fragment Flag: %d", (allData.getip(row)->flags_fo & 0x4000) >> 14);
        entry = QString(buf);
        QTreeWidgetItem *flag1 = new QTreeWidgetItem(level3);
        flag1->setText(0, entry);

        sprintf(buf, "(More Fragment Flag: %d", (allData.getip(row)->flags_fo & 0x2000) >> 13);
        entry = QString(buf);
        QTreeWidgetItem *flag3 = new QTreeWidgetItem(level3);
        flag3->setText(0, entry);

        sprintf(buf, "Offset: %d", allData.getip(row)->flags_fo & 0x1fff);
        entry = QString(buf);
        QTreeWidgetItem *ipOffset = new QTreeWidgetItem(level3);
        ipOffset->setText(0, entry);

        sprintf(buf, "Time To Live: %d", allData.getip(row)->ttl);
        entry = QString(buf);
        QTreeWidgetItem *ipTTL = new QTreeWidgetItem(level3);
        ipTTL->setText(0, entry);

        sprintf(buf, "Protocol: %d", allData.getip(row)->proto);
        entry = QString(buf);
        QTreeWidgetItem *ipProto = new QTreeWidgetItem(level3);
        ipProto->setText(0, entry);

        sprintf(buf, "Header Checksum: 0x%04x", allData.getip(row)->crc);
        entry = QString(buf);
        QTreeWidgetItem *ipHCheckSum = new QTreeWidgetItem(level3);
        ipHCheckSum->setText(0, entry);

        sprintf(buf, "%s", (std::string(allData.getip(row)->saddr)).c_str());
        entry = "Source IP: " + QString(buf);
        QTreeWidgetItem *ipSrcIp = new QTreeWidgetItem(level3);
        ipSrcIp->setText(0, entry);

        sprintf(buf, "%s", (std::string(allData.getip(row)->daddr)).c_str());
        entry = "Destination IP: " + QString(buf);
        QTreeWidgetItem *ipDestIp = new QTreeWidgetItem(level3);
        ipDestIp->setText(0, entry);

        if(target->type == "TCP")
        {
            entry = QString("TCP Header");
            QTreeWidgetItem *level5 = new QTreeWidgetItem(root);
            level5->setText(0, entry);

            sprintf(buf, "Source Port: %d", allData.gettcp(row)->sourcePort);
            entry = QString(buf);
            QTreeWidgetItem *tcpSrcPort = new QTreeWidgetItem(level5);
            tcpSrcPort->setText(0, entry);

            sprintf(buf, "Destination Port: %d", allData.gettcp(row)->destinationPort);
            entry = QString(buf);
            QTreeWidgetItem *tcpDestPort = new QTreeWidgetItem(level5);
            tcpDestPort->setText(0, entry);

            sprintf(buf, "Sequence Number: 0x%08x", allData.gettcp(row)->sequenceNumber);
            entry = QString(buf);
            QTreeWidgetItem *tcpSeq = new QTreeWidgetItem(level5);
            tcpSeq->setText(0, entry);

            sprintf(buf, "Acknoledge Number: 0x%08x", allData.gettcp(row)->acknowledgeNumber);
            entry = QString(buf);
            QTreeWidgetItem *tcpAck = new QTreeWidgetItem(level5);
            tcpAck->setText(0, entry);

            sprintf(buf, "Header Length: %d bytes (%d)", ((allData.gettcp(row)->dataoffset >> 4)&0x0f) * 4, (allData.gettcp(row)->dataoffset >> 4)&0x0f);
            entry = QString(buf);
            QTreeWidgetItem *tcpOFF = new QTreeWidgetItem(level5);
            tcpOFF->setText(0, entry);

            sprintf(buf, "FLAG: 0x%02x", allData.gettcp(row)->flags & 0x3f);
            entry = QString(buf);
            QTreeWidgetItem *tcpFlag = new QTreeWidgetItem(level5);
            tcpFlag->setText(0, entry);

            sprintf(buf, "URG: %d", (allData.gettcp(row)->flags & 0x20) >> 5);
            entry = QString(buf);
            QTreeWidgetItem *urgflag = new QTreeWidgetItem(tcpFlag);
            urgflag->setText(0, entry);

            sprintf(buf, "ACK: %d", (allData.gettcp(row)->flags & 0x10) >> 4);
            entry = QString(buf);
            QTreeWidgetItem *ackflag = new QTreeWidgetItem(tcpFlag);
            ackflag->setText(0, entry);

            sprintf(buf, "PUSH: %d", (allData.gettcp(row)->flags & 0x08) >> 3);
            entry = QString(buf);
            QTreeWidgetItem *pushflag = new QTreeWidgetItem(tcpFlag);
            pushflag->setText(0, entry);

            sprintf(buf, "RST: %d", (allData.gettcp(row)->flags & 0x04) >> 2);
            entry = QString(buf);
            QTreeWidgetItem *rstflag = new QTreeWidgetItem(tcpFlag);
            rstflag->setText(0, entry);

            sprintf(buf, "SYN: %d", (allData.gettcp(row)->flags & 0x02) >> 1);
            entry = QString(buf);
            QTreeWidgetItem *synflag = new QTreeWidgetItem(tcpFlag);
            synflag->setText(0, entry);

            sprintf(buf, "FIN: %d", (allData.gettcp(row)->flags & 0x01));
            entry = QString(buf);
            QTreeWidgetItem *finflag = new QTreeWidgetItem(tcpFlag);
            finflag->setText(0, entry);

            sprintf(buf, "Windows Size: %d", allData.gettcp(row)->windows);
            entry = QString(buf);
            QTreeWidgetItem *tcpWndSize = new QTreeWidgetItem(level5);
            tcpWndSize->setText(0, entry);

            sprintf(buf, "Checksum: 0x%04x", allData.gettcp(row)->checksum);
            entry = QString(buf);
            QTreeWidgetItem *tcpCheck = new QTreeWidgetItem(level5);
            tcpCheck->setText(0, entry);

            sprintf(buf, "Urgent Pointer: %d", allData.gettcp(row)->urgentPointer);
            entry = QString(buf);
            QTreeWidgetItem *tcpUrgPtr = new QTreeWidgetItem(level5);
            tcpUrgPtr->setText(0, entry);
        }
        else if(target->type == "UDP")
        {
            //添加UDP协议头
            entry = QString("UDP Header");
            QTreeWidgetItem *level6 = new QTreeWidgetItem(root);
            level6->setText(0, entry);

            sprintf(buf, "Source Port: %d", allData.getudp(row)->sourcePort);
            entry = QString(buf);
            QTreeWidgetItem *udpSrcPort = new QTreeWidgetItem(level6);
            udpSrcPort->setText(0, entry);

            sprintf(buf, "Destination Port: %d", allData.getudp(row)->destinationPort);
            entry = QString(buf);
            QTreeWidgetItem *udpDestPort = new QTreeWidgetItem(level6);
            udpDestPort->setText(0, entry);

            sprintf(buf, "Total Length: %d", allData.getudp(row)->len);
            entry = QString(buf);
            QTreeWidgetItem *udpLen = new QTreeWidgetItem(level6);
            udpLen->setText(0, entry);

            sprintf(buf, "Checksum: 0x%04x", allData.getudp(row)->checksum);
            entry = QString(buf);
            QTreeWidgetItem *udpCrc = new QTreeWidgetItem(level6);
            udpCrc->setText(0, entry);
        }
        else if(target->type == "ICMP")
        {
            //添加ICMP协议头
            entry = QString("ICMP Header");
            QTreeWidgetItem *level4 = new QTreeWidgetItem(root);
            level4->setText(0, entry);

            sprintf(buf, "Type: %d", allData.geticmp(row)->icmp_type);
            entry = QString(buf);
            QTreeWidgetItem *icmpType = new QTreeWidgetItem(level4);
            icmpType->setText(0, entry);

            sprintf(buf, "Code: %d", allData.geticmp(row)->icmp_code);
            entry = QString(buf);
            QTreeWidgetItem *icmpCode = new QTreeWidgetItem(level4);
            icmpCode->setText(0, entry);

            sprintf(buf, "Checksum: 0x%04x", allData.geticmp(row)->icmp_checksum);
            entry = QString(buf);
            QTreeWidgetItem *icmpCheck = new QTreeWidgetItem(level4);
            icmpCheck->setText(0, entry);

            sprintf(buf, "Identification: 0x%04x", allData.geticmp(row)->icmp_id);
            entry = QString(buf);
            QTreeWidgetItem *icmpIdentify = new QTreeWidgetItem(level4);
            icmpIdentify->setText(0, entry);

            sprintf(buf, "Sequence Number: 0x%04x", allData.geticmp(row)->icmp_sequence);
            entry = QString(buf);
            QTreeWidgetItem *icmpSeq = new QTreeWidgetItem(level4);
            icmpSeq->setText(0, entry);

        }
        else if(target->type == "IGMP")
        {
            //添加IGMP协议头
            entry = QString("IGMP Header");
            QTreeWidgetItem *level4 = new QTreeWidgetItem(root);
            level4->setText(0, entry);

            sprintf(buf, "Version: %d", allData.getigmp(row)->hVerType & 0xf0 >> 4);
            entry = QString(buf);
            QTreeWidgetItem *igmpVer = new QTreeWidgetItem(level4);
            igmpVer->setText(0, entry);

            sprintf(buf, "Type: %d", allData.getigmp(row)->hVerType & 0x0f);
            entry = QString(buf);
            QTreeWidgetItem *icmpType = new QTreeWidgetItem(level4);
            icmpType->setText(0, entry);

            sprintf(buf, "Checksum: 0x%04x", allData.getigmp(row)->uCheckSum);
            entry = QString(buf);
            QTreeWidgetItem *igmpCheck = new QTreeWidgetItem(level4);
            igmpCheck->setText(0, entry);

            sprintf(buf, "Group Address: %s", ((std::string)allData.getigmp(row)->dwGroupAddress).c_str());
            entry = QString(buf);
            QTreeWidgetItem *igmpAddr = new QTreeWidgetItem(level4);
            igmpAddr->setText(0, entry);
        }
    }
}
// display all the data
void Dialog::showHexData(int index)
{
    // get data and length
    ui->hexData->clear();
    const u_char *print_data = allData.getCont(size_t(index))->data;
    int print_len = static_cast<int>(allData.getCont(size_t(index))->len);
    QString tempnum,tempchar;
    QString oneline;
    int i;
    tempchar = "  ";
    oneline = "";
    qDebug() << "select " << index << endl;
    qDebug() << *print_data << endl;
    for(i = 0 ; i < print_len ; i ++){
        if(i % 16 == 0){
            //输出行号
            oneline += tempnum.sprintf("%04x  ",i);
        }
        oneline += tempnum.sprintf("%02x ",print_data[i]);
        if(isprint(print_data[i])){     //判断是否为可打印字符
            tempchar += static_cast<char>(print_data[i]);
        }
        else{
            tempchar += ".";
        }
        if((i+1)%16 == 0){
            ui->hexData->append(oneline + tempchar);
            tempchar = "  ";
            oneline = "";
        }
    }
    i %= 16;
    for(; i < 16 ; i ++){
        oneline += "   ";
    }
    ui->hexData->append(oneline + tempchar);
}
