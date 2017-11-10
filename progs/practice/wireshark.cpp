#include "wireshark.h"
#include "ui_wireshark.h"
#include <QDateTime>
using namespace std;

Wireshark::Wireshark(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Wireshark)
{
    ui->setupUi(this);
}
Wireshark::~Wireshark()
{
    delete ui;
}

struct WR
{
    int len,num,a,b;
};
vector<WR> M(0),COPY(0);
void Wireshark::on_pushButton_clicked()
{
    QString Name="";
    Name = QFileDialog::getOpenFileName(this,"Open File","","Pcap files (*.cap)");
    if(Name!="")
    {

        fstream F;
        ui->label->setText(Name);
        F.open(Name.toLocal8Bit().data(),ios::in | ios::binary);
        int sme=24;
        F.seekg(sizeof(char),ios::end);
        int SIZE=F.tellp();
        F.seekg(sizeof(char),ios::beg);
        F.seekg(sizeof(char)*sme);
        PackHead PakH;
        M.clear();
        WR Image;
        int i=1;

        while(sme<=SIZE)
        {
            F.read((char*)&PakH,sizeof(PackHead));
            sme+=16;
            Image.len=PakH.len;
            Image.num=i;
            Image.a=PakH.a;
            Image.b=PakH.b;
            M.push_back(Image);
            i++;
            sme+=PakH.len;
            F.seekg(sizeof(char)*sme);
        }

        M.pop_back();
        int length=M.size();
        ui->lcdNumber->display(length);
        ui->lineEdit->setEnabled(true);
        ui->lineEdit_2->setEnabled(true);
        ui->lineEdit->setText("1");
        ui->lineEdit_2->setText(QString::number(length));
        ui->radioButton->setEnabled(true);
        ui->radioButton_2->setEnabled(true);
        ui->pushButton_2->setEnabled(true);
        ui->radioButton_2->setChecked(true);
        on_pushButton_2_clicked();
        F.close();
    }
}

void MERGE(int a,int b)
{
    for(int i=a;i<=b;i++)
        COPY.push_back(M[i]);
}

bool Comp1(WR A,WR B)
{
    if(A.len==B.len)
        return A.num<B.num;
    return A.len<B.len;
}
bool Comp2(WR A,WR B)
{
    return A.num<B.num;
}

void Wireshark::on_pushButton_2_clicked()
{
    int START=(ui->lineEdit->text()).toInt()-1;
    int END=(ui->lineEdit_2->text()).toInt()-1;
    ui->textEdit->clear();
    int checker=0;
    if(END>M.size())
    {
        END=M.size();
        ui->lineEdit_2->setText(QString::number(M.size()));
    }
    COPY.clear();
    MERGE(START,END);

    if(ui->radioButton->isChecked()==true)
    {
        sort(COPY.begin(),COPY.end(),Comp1);
    }
    else
    {
        sort(COPY.begin(),COPY.end(),Comp2);
    }
    double MED=0;
    int MAX=-1,MIN=-1;
    for(int i=0;i<(int)COPY.size();i++)
    {
        if(checker<=100)
        {
            QString INFO="";
            INFO+="Packet Number";
            INFO+=QString::number(COPY[i].num);
            INFO+=":\n/////////////////////////////////////////////////////////\n\t   Length = ";
            INFO+=QString::number(COPY[i].len);
            INFO+=" byte\n\t   First Time = ";
            INFO+=(QDateTime::fromTime_t(COPY[i].a)).toString();
            INFO+="\n\t   Second Time = ";
            INFO+=(QDateTime::fromTime_t(COPY[i].b)).toString();
            INFO+="\n/////////////////////////////////////////////////////////";
            ui->textEdit->append(INFO);
            ui->textEdit->append("");
         }
        checker++;
        MED+=COPY[i].len;
        if(MAX<COPY[i].len || MAX==-1)
           MAX=COPY[i].len;
        if(MIN>COPY[i].len || MIN==-1)
           MIN=COPY[i].len;

    }
    if(checker>100)
         ui->textEdit->append("Файл слишком велик.\nОтображены только 100 пакетов..");
    MED=MED/COPY.size();
    ui->lcdNumber_2->display(MED);
    ui->lcdNumber_3->display(MAX);
    ui->lcdNumber_4->display(MIN);
}
