/*
 * Description : Program Entrance
 * Author:  YangLei
 */
#include "mainwindow.h"
#include <QApplication>
#include <pcap.h>
#include <pcap-stdinc.h>

// all thevariables
int selectDev = 0;
int devCount = 0;
pcap_if_t* allDevs = nullptr;
pcap_if_t* d = nullptr;
pcap_t* adhandle = nullptr;
pcap_dumper_t* dumpfile = nullptr;
char errbuf[PCAP_ERRBUF_SIZE + 1];
char* filter = nullptr;
pkgcount pkgcounter;
PacketList allData;
capThread* capthread = nullptr;
std::vector<int> selectedData;
std::string keyword;
regrouped_data tcp_regrouped;
int selected;
bool isIPgroup;

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    w.show();

    return a.exec();
}
