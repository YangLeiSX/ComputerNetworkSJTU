/*
 * File: tcpdialog.cpp
 * Description : dialog to display tcp regroup result
 * Author:  Cao Yuqin
 */
#include "tcpdialog.h"
#include "ui_tcpdialog.h"

TCPDialog::TCPDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::TCPDialog)
{
    ui->setupUi(this);
    this->setWindowTitle("Regroup Result");
    ui->hexData->clear();
    display();
}

TCPDialog::~TCPDialog()
{
    delete ui;
}

void TCPDialog::display()
{
    const u_char *print_data = tcp_regrouped.data;
    u_int print_len = tcp_regrouped.total_len;
    QString tempnum,tempchar;
    QString oneline;
    int i;
    tempchar = "  ";
    oneline = "";
    qDebug() << *print_data << endl;
    for(i = 0 ; i < static_cast<int>(print_len) ; i ++){
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

