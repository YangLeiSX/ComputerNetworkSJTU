/*
 * Description : Main Window
 * Author:  YangLei
 */
#include "mainwindow.h"
#include "ui_mainwindow.h"

// on create the main window
MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    // setup the main window
    this->setWindowTitle("Wow, You Can Really Sniff");
    this->setMinimumSize(1200,900);
    this->minimumSize();
    setupMenus();
    setupDisplay();
    setupDetail();
    setupSelect();
    // get internet devices
    initDevs();
    if(devCount < 0)
    {
        QMessageBox::warning(this, tr("Wow, You Can Really Sniff"), tr("Sorry I cannot find any devices!"), QMessageBox::Ok);
    }
    // display the devices for select
    for(d = allDevs; d != nullptr ; d = d->next)
    {
        ui->boxIface->addItem(QString("%1").arg(d->description));
    }
    pcap_freealldevs(allDevs);
    allDevs = nullptr;
    // initialize other variables
    RowCount = 0;
    isFileSaved = false;
    isIPgroup = false;
    capthread = nullptr;
    selected = -1;
}

MainWindow::~MainWindow()
{
    delete ui;
}
// setup the display part
void MainWindow::setupDisplay()
{
    // setup the dispaly table
    ui->tableData->setColumnCount(7);
    ui->tableData->setHorizontalHeaderLabels(QStringList() << tr("No.") << tr("Time")
                                             << tr("Source IP") << tr("Destination IP")
                                              << tr("Protocol") << tr("Length") << tr("Abstract"));
    ui->tableData->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tableData->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->tableData->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->tableData->setColumnWidth(0, 120);
    ui->tableData->setColumnWidth(1, 180);
    ui->tableData->setColumnWidth(2, 180);
    ui->tableData->setColumnWidth(3, 180);
    ui->tableData->setColumnWidth(4, 120);
    ui->tableData->setColumnWidth(5, 120);
    ui->tableData->setColumnWidth(6, 640);
    // when clicked, show header detail and data
    connect(ui->tableData, SIGNAL(cellClicked(int,int)), this, SLOT(showDetail(int, int)));
    ui->tableData->verticalHeader()->setVisible(false);
    // setup the "IP regroup" checker
    ui->checkIP->setEnabled(true);
    ui->checkIP->setChecked(false);
    ui->buttonTCP->setEnabled(ui->checkIP->checkState());
}
// setup the header detail part
void MainWindow::setupDetail()
{
    // set up the header detail part
    ui->detailPart->setHeaderLabel("Protocol Detail of the Packet");
    ui->detailPart->setColumnCount(1);
    ui->detailPart->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
    ui->detailPart->header()->setStretchLastSection(false);
    // clear the data part
    ui->hexData->clear();
}
// setup the device select part
void MainWindow::setupSelect()
{
    // add the information
    ui->boxIface->addItem(tr("Please Select an Interface"));
    // disable the stop button
    ui->buttonStop->setEnabled(false);
}
// setup the menus bar (actually useless)
void MainWindow::setupMenus()
{
    // add two action to savefile and exit
    actionSave = new QAction(tr("Save"), this);
    actionExit = new QAction(tr("Exit"), this);
    connect(actionSave, SIGNAL(triggered()), this, SLOT(slotsave()));
    connect(actionExit, SIGNAL(triggered()), this, SLOT(close()));
    // add the action to the menu
    fileMenu = this->menuBar()->addMenu(tr("File"));
    fileMenu->addAction(actionSave);
    fileMenu->addAction(actionExit);
}
// click the start button
void MainWindow::on_buttonStart_clicked()
{
    // check the data buffer and ask for save
    if(isFileSaved == false && RowCount != 0)
    {
        int choice;
        choice = QMessageBox::information(this, "Wow, You Can Really Sniff",
                                          tr("You have unsaved data, save it or not?"),
                                             QMessageBox::Save, QMessageBox::Cancel);
        if(choice == QMessageBox::Save)
            // save the data
            savefile();
        else if(choice == QMessageBox::Cancel)
            isFileSaved = true;
    }
    // clear the data buffer and initialize
    clearPcap();
    ui->detailPart->clear();
    ui->tableData->clearContents();
    ui->tableData->setRowCount(0);
    ui->hexData->clear();
    ui->detailPart->clear();
    ui->numIp->setText(QString::number(0));
    ui->numIcmp->setText((QString::number(0)));
    ui->numTcp->setText(QString::number(0));
    ui->numUdp->setText(QString::number(0));
    ui->numArp->setText(QString::number(0));
    ui->numOther->setText(QString::number(0));
    ui->numFlow->setText(QString::number(0));
    ui->numGram->setText(QString::number(0));
    ui->checkIP->setEnabled(false);
    // get current path for temporary file
    QString path = QDir::currentPath();
    qDebug() << "currect path is " << path << endl;
    QString saveDir = path + "/SavedData";
    QDir dir(saveDir);
    if(!dir.exists())
    {
        // make the directory
        if(!dir.mkdir(saveDir))
        {
            QMessageBox::warning(this, "Sniff Warning", tr("Fail to make temporary directory!"),
                                 QMessageBox::Ok);
            return ;
        }
    }
    // get current time
    char thistime[30];
    struct tm *ltime;
    time_t nowtime;
    time(&nowtime);
    ltime = localtime(&nowtime);
    strftime(thistime, sizeof(thistime),"%Y%m%d_%H%M%S", ltime);
    qDebug() << "time is:" << thistime << endl;
    // get temporary file path
    std::string str = saveDir.toStdString();
    strcpy(filepath, str.c_str());
    strcat(filepath, "/");
    strcat(filepath, thistime);
    strcat(filepath, ".pcap");
    qDebug() << "data save path is " + QString(filepath) << endl;
    // begin to capture
    if(beginPcap())
        return ;
    // disable button begin and enable button stop
    ui->buttonStart->setEnabled(false);
    ui->buttonStop->setEnabled(true);
    actionSave->setEnabled(false);
    isFileSaved = false;
}
// click the stop button
void MainWindow::on_buttonStop_clicked()
{
    qDebug() << "STOP!"<< endl;
    // disable the stop button and enable start button
    ui->buttonStart->setEnabled(true);
    ui->buttonStop->setEnabled(false);
    ui->checkIP->setEnabled(true);
    actionSave->setEnabled(true);
    // sop to capture
    capthread->stop();
}
// click the svcae button
void MainWindow::on_buttonSave_clicked()
{
    savefile();
    qDebug() << "save\n";
}
// trigger the save action
void MainWindow::slotsave()
{
    savefile();
    isFileSaved = true;
    qDebug() << "save" << endl;
}
// get the devices(interfaces)
void MainWindow::initDevs()
{
    // clear
    devCount = 0;
    selectDev = -1;
    // try to get the devices
    if (pcap_findalldevs_ex(const_cast<char *>(PCAP_SRC_IF_STRING), nullptr, &allDevs, errbuf) == -1)
    {
        // fail to get the devices
        qDebug() << "pcap_findalldevs_ex返回设备列表错误：%s\n";
        exit(1);
    }
    // print the devices for debug
    for (d = allDevs; d != nullptr; d = d->next)
    {
        qDebug() << devCount++ << " " << d->name << endl;
        if (d->description)
            qDebug() << d->description << endl;
        else
            qDebug() << "(无描述信息)\n";
    }
    qDebug() << "total device number" << devCount << endl;
    if (devCount == 0)
    {
        qDebug() << "\n没有找到设备列表！确认winPcap已经正确安装...\n";
        exit(0);
    }
}
// clear all the data
void MainWindow::clearPcap()
{
    selected = -1;
    devCount = 0;
    selectDev = -1;
    if(allDevs)
    {
        pcap_freealldevs(allDevs);
        allDevs = nullptr;
    }
    if(d)
        d = allDevs;
    if(capthread)
    {
        delete capthread;
        capthread = nullptr;
    }
    filter = nullptr;
    pkgcounter.n_tcp = pkgcounter.n_udp = pkgcounter.n_ip = pkgcounter.n_icmp = 0;
    pkgcounter.n_arp = pkgcounter.n_other = pkgcounter.n_sum = pkgcounter.d_sum = 0;
    allData.clear();
    isFileSaved = false;
}
// begin to capture
int MainWindow::beginPcap()
{
    // get the devices
    initDevs();
    if(!(selectDev = ui->boxIface->currentIndex())){
        QMessageBox::warning(this, "Wow, You Can Really Sniff",tr("You should select an interface!"),
                                    QMessageBox::Ok);
        return 1;
    }
    else{
        qDebug() << "selected device:" << selectDev << endl;
    }
    d = allDevs;
    for (int i = 1; i < selectDev;i++)
        d = d->next;
    qDebug() << "get device " << d->description << endl;

    // open the device
    if ((adhandle = pcap_open_live(d->name,         //设备名
        65536,                                 //65535保证能捕捉到不同数据链路层上的每个数据包的全部内容（比最大MTU还大）
        PCAP_OPENFLAG_PROMISCUOUS,             //混杂模式
        1000,                                  //读取超时时间
        errbuf                                 //错误缓冲池
        )) == nullptr)
    {// fail to open the devices
        qDebug() << "\n不能打开适配器，%s WinPcap不支持该适配器" << d->name << endl;
        // free the device list
        pcap_freealldevs(allDevs);
        allDevs = nullptr;
        exit(-1);
    }
    else{
        qDebug() << "\n开始侦听" << d->description << endl;
        // feree the devices list
        pcap_freealldevs(allDevs);
        allDevs = nullptr;
    }
    // cheack environment
    struct bpf_program fcode;
    u_int netmask = 0xffffff;
    if(pcap_datalink(adhandle) != DLT_EN10MB)
    {
        QMessageBox::warning(this, "Wow, You Can Really Sniff", tr("Sorry, We Can Only Support Etrernet!"), QMessageBox::Ok);
        pcap_freealldevs(allDevs);
        allDevs = nullptr;
        exit(-1);
    }
    // get the filter content
    QString filterCont = ui->filterRule->text();
    qDebug() << "filter:" << filterCont << endl;
    if(filterCont == nullptr)
    {
        char filter[] = "";
        if(pcap_compile(adhandle, &fcode, filter, 1, netmask) < 0)
        {
            QMessageBox::warning(this, "Wow, You Can Really Snifff", tr("Fail to Compile the Filter, Please Check It"), QMessageBox::Ok);
            pcap_freealldevs(allDevs);
            allDevs = nullptr;
            exit(1);
        }
    }
    else{
        QByteArray ba = filterCont.toLatin1();
        char *filter = nullptr;
        filter = ba.data();     //上述转换中要求QString中不含有中文，否则会出现乱码
        if(pcap_compile(adhandle, &fcode, filter, 1, netmask) < 0)
        {
            QMessageBox::warning(this, "Wow, You Can Really Snifff", tr("Fail to Compile the Filter, Please Check It"), QMessageBox::Ok);
            pcap_freealldevs(allDevs);
            allDevs = nullptr;
            exit(-1);
        }

    }
    // set up the filter
    if(pcap_setfilter(adhandle, &fcode) < 0)
    {
        QMessageBox::warning(this, "Wow, You Can Really Sniff", tr("There is Something Wrong!"), QMessageBox::Ok);
        pcap_freealldevs(allDevs);
        allDevs = nullptr;
        exit(-1);
    }
    // open the temporary file
    dumpfile = pcap_dump_open(adhandle, filepath);
    if(dumpfile == nullptr)
    {
        QMessageBox::warning(this, "Sniff Warning",
                             tr("Fail to Open TemporaryFile"), QMessageBox::Ok);
        exit(-1);
    }
    // create the capture thread
    capthread = new capThread(adhandle, pkgcounter, allData, dumpfile);
    qDebug() << "setup new thread!" << endl;
    // set up the slots for udate
    connect(capthread, SIGNAL(addOneLine(QString,QString,QString,QString,QString,QString)), this, SLOT(updateTable(QString,QString,QString,QString,QString,QString)));
    connect(capthread, SIGNAL(updateCount()), SLOT(updateNum()));
    // start the thread
    capthread->start();
    qDebug() << "thread run!";
    return 0;
}

// opdate the table
void MainWindow::updateTable(QString timestr, QString srcIP, QString dstIP, QString proto, QString length, QString summarize)
{
    // get the rowcount and insert a row
    qDebug() << "update table\n";
    RowCount = ui->tableData->rowCount();
    ui->tableData->insertRow(RowCount);
    QString orderNum = QString::number(RowCount+1, 10);
    // insert the table item
    ui->tableData->setItem(RowCount, 0, new QTableWidgetItem(orderNum));
    ui->tableData->setItem(RowCount, 1, new QTableWidgetItem(timestr));
    ui->tableData->setItem(RowCount, 2, new QTableWidgetItem(srcIP));
    ui->tableData->setItem(RowCount, 3, new QTableWidgetItem(dstIP));
    ui->tableData->setItem(RowCount, 4, new QTableWidgetItem(proto));
    ui->tableData->setItem(RowCount, 5, new QTableWidgetItem(length));
    ui->tableData->setItem(RowCount, 6, new QTableWidgetItem(summarize));
    if(RowCount > 1)
    {
        ui->tableData->scrollToItem(ui->tableData->item(RowCount, 0), QAbstractItemView::PositionAtBottom);
    }
    // set the color of the table item
    QColor color;
    if(proto == "TCP" || proto == "HTTP" ){
        // green
        color = QColor(228,255,199);
    }
    else if(proto == "IPV6"){
        // white
        color = QColor(255,255,255);
    }
    else if(proto == "UDP"){
        // blue
        color = QColor(218,238,255);
    }
    else if(proto == "ARP" || proto == "RARP"){
        // orage
        color = QColor(250,240,215);
    }
    else if(proto == "ICMP" || proto == "IGMP"){
        // pink
        color = QColor(252,224,255);
    }
    for(int i = 0; i < 7 ; i ++){
        ui->tableData->item(RowCount,i)->setBackgroundColor(color);
    }

}

// update the num counter
void MainWindow::updateNum()
{
    ui->numIp->setText(QString::number(pkgcounter.n_ip));
    ui->numIcmp->setText((QString::number(pkgcounter.n_icmp)));
    ui->numTcp->setText(QString::number(pkgcounter.n_tcp));
    ui->numUdp->setText(QString::number(pkgcounter.n_udp));
    ui->numArp->setText(QString::number(pkgcounter.n_arp));
    ui->numOther->setText(QString::number(pkgcounter.n_other));
    ui->numFlow->setText(QString::number(pkgcounter.d_sum));
    ui->numGram->setText(QString::number(pkgcounter.n_sum));
}
// show the header detail
void MainWindow::showDetail(int row, int column)
{
    qDebug() << row << " " << column << endl;
    // get the selected packet index
    selected = row;
    ui->hexData->clear();
    ui->detailPart->clear();
    // display all the data
    showHexData(row);
    // get the target packet
    packet *target = allData.getCont(static_cast<size_t>(row));

    // entry for tree key
    // buf for displayed string
    QString entry;
    char buf[100];
    // root key
    sprintf(buf, "Selected Packet is No.%d", row+1);
    entry = QString(buf);
    QTreeWidgetItem *root = new QTreeWidgetItem(ui->detailPart);
    root->setText(0, entry);

    // data link layer
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

    // network layer
    if(target->type == "ARP")
    {
        // arp header
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
        // RARP Header
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
        // IPV6 Header
        entry = QString("IPV6 Header");
        QTreeWidgetItem *level3 = new QTreeWidgetItem(root);
        level3->setText(0, entry);

        sprintf(buf, "Version : %d", (allData.getip6(row)->ver_tf & 0xf0) >> 4);
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

        sprintf(buf, "Total Length: %d", allData.getip6(row)->length[0]*16+allData.getip6(row)->length[1]);
        entry = QString(buf);
        QTreeWidgetItem *ipTotalLen = new QTreeWidgetItem(level3);
        ipTotalLen->setText(0, entry);

        sprintf(buf, "Next Header: %02x", allData.getip6(row)->next_header);
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
        // IP Header
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

        sprintf(buf, "More Fragment Flag: %d", (allData.getip(row)->flags_fo & 0x2000) >> 13);
        entry = QString(buf);
        QTreeWidgetItem *flag3 = new QTreeWidgetItem(level3);
        flag3->setText(0, entry);

        sprintf(buf, "Offset: %d", (allData.getip(row)->flags_fo & 0x1fff));
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

        if(target->type == "TCP" || target->type == "HTTP")
        {
            // TCP Header
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

            qDebug() << allData.gettcp(row)->flags << endl;
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
            // UDP Header
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
            // ICMP Header
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
            // IGMP Header
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

            sprintf(buf, "Group Address: %s", (std::string(allData.getigmp(row)->dwGroupAddress)).c_str());
            entry = QString(buf);
            QTreeWidgetItem *igmpAddr = new QTreeWidgetItem(level4);
            igmpAddr->setText(0, entry);
        }
    }
}
// dispaly all the data
void MainWindow::showHexData(int index)
{
    // get the data and length
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
            // line index
            oneline += tempnum.sprintf("%04x  ",i);
        }
        oneline += tempnum.sprintf("%02x ",print_data[i]);
        if(isprint(print_data[i])){
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
// save the data to file
void MainWindow::savefile()
{
    // get save file name
    QString filename = QFileDialog::getSaveFileName(this,
                                    tr("save"),".",
                                    tr("Sniffer data file(*.pcap)"));
    QString curFile = QString(filepath);
    // check filename
    if(curFile.isEmpty())
        return ;
    if(filename.isEmpty())
        return ;
    // copy temporary file to target file
    if(!QFile::copy(curFile, filename))
    {
        QMessageBox::warning(this, "Wow,You Can Really Sniff", "Fail to save the data!",QMessageBox::Ok);
        return ;
    }
    qDebug() << filename << endl;
    QMessageBox::information(this, "Wow, You Can Really Sniff", tr("Data Saved Successfully!"),QMessageBox::Ok);
    isFileSaved = true;
}
// close the mainwindow and quit
void MainWindow::closeEvent(QCloseEvent *event)
{

    // double check
    int ret = QMessageBox::information(this, "Wow, You Can Really Sniff",
                                       tr("Are You Ready to Exit?"), QMessageBox::Yes, QMessageBox::No);
    if(ret == QMessageBox::Yes)
    {
        if(isFileSaved == false && RowCount != 0)
        {
            int ret;
            ret = QMessageBox::information(this, "Wow, You Can Really Sniff",
                                           tr("You Have Not Save Your Data, Do You Want to Save It?"),QMessageBox::Save, QMessageBox::No);
            if(ret == QMessageBox::Save)
            {
                    savefile();

            }
            else if(ret == QMessageBox::No)
                ;// do nothing
        }
        qDebug() << "STOP!"<< endl;
        if(capthread->isRunning())
        {
            // change the status
            ui->buttonStart->setEnabled(true);
            ui->buttonStop->setEnabled(false);
            ui->checkIP->setEnabled(true);
            actionSave->setEnabled(true);
            // stop capture thread
            capthread->stop();
            // close the device
            pcap_close(adhandle);
        }
        clearPcap();
        // exit
        event->accept();
    }
    else {
        // donot exit
        event->ignore();
    }
}
// search for keyword
void MainWindow::on_buttonSearch_clicked()
{
    // ignore if no data
    if(RowCount == 0)
        return ;
    // get the keyward
    keyword = std::string(ui->searchRule->text().toLatin1().data());
    if(!selectedData.empty())
        selectedData.clear();
    // search for keyword
    selectedData = allData.search(keyword);
    qDebug() << "begin search" << ui->searchRule->text();
    qDebug() << "found " << selectedData.size() << endl;
    // display the result
    QDialog *searchResult = new Dialog();
    searchResult->exec();
}
// change the ip regroup check box
void MainWindow::on_checkIP_stateChanged(int arg1)
{
    qDebug() << arg1 << endl;
    ui->buttonTCP->setEnabled(ui->checkIP->checkState());
    isIPgroup = ui->checkIP->checkState();
}
// tcp regroup
void MainWindow::on_buttonTCP_clicked()
{
    // if not select a packet
    if(selected < 0)
    {
        QMessageBox::information(this, "Wow, You Can Really Sniff",
                                 "You Should Select a Packet!", QMessageBox::Ok);
        return ;
    }
    // if not a TCP packet
    if(allData.getCont(static_cast<size_t>(selected))->type != "TCP" && allData.getCont(static_cast<size_t>(selected))->type != "HTTP")
    {
        QMessageBox::information(this, "TCP Regroup",
                                 "you should selected a TCP packet!", QMessageBox::Ok);
        return ;
    }
    // get regrouped data and length
    allData.tcp_regroup(static_cast<size_t>(selected), tcp_regrouped.data, tcp_regrouped.total_len);
    // print the data for debug
    u_int i = 0;
    uchar* byte = tcp_regrouped.data;
    for(i = 0, byte = tcp_regrouped.data; i < tcp_regrouped.total_len;i++,byte++)
        qDebug() << *byte << " ";
    // display the data
    QDialog *regroupResult = new TCPDialog();
    regroupResult->exec();
    // clear the data
    delete tcp_regrouped.data;
    tcp_regrouped.data = nullptr;
    tcp_regrouped.total_len = 0;
}
