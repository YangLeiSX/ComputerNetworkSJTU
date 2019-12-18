#-------------------------------------------------
#
# Project created by QtCreator 2019-12-09T18:38:29
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = Sniff
TEMPLATE = app

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

CONFIG += c++11

SOURCES += \
        main.cpp \
        mainwindow.cpp \
    packetlist.cpp \
    ipv6.cpp \
    ipv4.cpp \
    arp.cpp \
    rarp.cpp \
    capthread.cpp \
    dialog.cpp \
    tcpdialog.cpp

HEADERS += \
        mainwindow.h \
    global.h \
    protocol.h \
    dialog.h \
    tcpdialog.h

FORMS += \
        mainwindow.ui \
    dialog.ui \
    tcpdialog.ui

INCLUDEPATH += C:\WpdPack\Include

LIBS += -L C:\WpdPack\Lib\*.a

LIBS += -L C:\WpdPack\Lib\x64\Packet.lib

LIBS += -L C:\WpdPack\Lib\x64\Wpcap.lib -lws2_32
# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

DISTFILES += \
    logo.rc \
    avatar.ico

RC_FILE += \
    logo.rc
