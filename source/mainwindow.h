/*
 * File: mainwindow.h
 * Description : main window class
 * Author:  Yang Lei
 */
#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "global.h"
#include "dialog.h"
#include "tcpdialog.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    // setup and initialize functions
    void setupMenus();
    void setupDisplay();
    void setupDetail();
    void setupSelect();
    void initDevs();
    // capture functions
    void clearPcap();
    int beginPcap();
    // other functions
    void savefile();
    void closeEvent(QCloseEvent *event);

    // variables
    int RowCount;       // packet number
    bool isFileSaved;   // file save status
    char filepath[512]; // file path buffer

private slots:
    // save action
    void slotsave();
    // dispaly results
    void updateTable(QString timestr, QString srcIP, QString dstIP, QString proto, QString length, QString summarize);
    void updateNum();
    // display details
    void showDetail(int, int);
    void showHexData(int);
    // handle buttons and check box
    void on_buttonStart_clicked();
    void on_buttonStop_clicked();
    void on_buttonSave_clicked();
    void on_buttonSearch_clicked();
    void on_buttonTCP_clicked();
    void on_checkIP_stateChanged(int arg1);

private:
    Ui::MainWindow *ui;
    QAction *actionSave;
    QAction *actionExit;
    QMenu *fileMenu;
};

#endif // MAINWINDOW_H
