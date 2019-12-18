/*
 * File: tcpdialog.h
 * Description : dialog for tco regroup result
 * Author:  Yang Lei
 */
#ifndef TCPDIALOG_H
#define TCPDIALOG_H

#include <QDialog>
#include "global.h"

namespace Ui {
class TCPDialog;
}

class TCPDialog : public QDialog
{
    Q_OBJECT

public:
    explicit TCPDialog(QWidget *parent = nullptr);
    ~TCPDialog();

    void display();
private:
    Ui::TCPDialog *ui;
};

#endif // TCPDIALOG_H
