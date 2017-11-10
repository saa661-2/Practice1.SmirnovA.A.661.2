#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "cal.h"
#include "wireshark.h"
MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_pushButton_clicked()
{

    cal= new Cal(this);
    cal->show();

}

void MainWindow::on_pushButton_2_clicked()
{
    wireshark= new Wireshark (this);
    wireshark->show();
}
