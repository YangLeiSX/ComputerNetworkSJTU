/*
 * File: dialog.h
 * Description : dialog window for search result
 * Author:  Yang Lei
 */
#ifndef DIALOG_H
#define DIALOG_H

#include <QDialog>

namespace Ui {
class Dialog;
}

class Dialog : public QDialog
{
    Q_OBJECT

public:
    explicit Dialog(QWidget *parent = nullptr);
    ~Dialog();

    int RowCount;
    void display();
private slots:
    void showDetail(int, int);
    void showHexData(int);
private:
    Ui::Dialog *ui;
};

#endif // DIALOG_H
