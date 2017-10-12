QT += core

CONFIG += c++14
INCLUDEPATH += "D:\Bunin\CN\WpdPack\Include"
INCLUDEPATH += "D:\Bunin\CN\WpdPack\Lib"
LIBS += -L"D:\Bunin\CN\WpdPack\Lib" -lwpcap -lpacket
LIBS += -lws2_32

TARGET = winpcap
CONFIG += console
CONFIG -= app_bundle
CONFIG +=Qt
TEMPLATE = app

SOURCES += main.cpp

HEADERS += \
    header.h \
    pack.h

FORMS +=
