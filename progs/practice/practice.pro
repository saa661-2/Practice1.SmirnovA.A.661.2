#-------------------------------------------------
#
# Project created by QtCreator 2017-10-23T13:03:59
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = practice
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp \
    cal.cpp \
    wireshark.cpp


HEADERS  += mainwindow.h \
    cal.h \
    wireshark.h


FORMS    += mainwindow.ui \
    cal.ui \
    wireshark.ui
