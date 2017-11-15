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
    vector<unsigned char> D;
};
vector<WR> M(0),COPY(0);
void Wireshark::on_pushButton_clicked()
{
    QString Name="";
    Name = QFileDialog::getOpenFileName(this,"Open File","","Pcap files (*.cap)");
    if(Name!="")
    {

        fstream F; //Поток связанный с файлом
        ui->label->setText(Name);
        F.open(Name.toLocal8Bit().data(),ios::in | ios::binary);
        int sme=24; //Не читаем общий заголовок смещение на 24 байта
        F.seekg(sizeof(char),ios::end);// указатель на конец
        int SIZE=F.tellp();//Сохранение конца файла
        F.seekg(sizeof(char),ios::beg);//указатель на начало
        F.seekg(sizeof(char)*sme);//смещение
        PackHead PakH;//Создание структуры с именем
        M.clear();//Очищаем M
        WR Image;//Образ структуры
        int i=1;

        while(sme<=SIZE)
        {
            F.read((char*)&PakH,sizeof(PackHead)); //Считываем структуру
            sme+=16; //Не читаем заголовок каждого пакета
            Image.len=PakH.len;
            Image.num=i;
            Image.a=PakH.a;   //Сохранение образов
            Image.b=PakH.b;
            int j=1;
            while(j<=PakH.len)
            {
                unsigned char p;
                F.read((char*)&p,sizeof(char));
                Image.D.push_back(p);
                j++;
            }
            M.push_back(Image);//Запушил в массив пакетов
            i++;
            sme+=PakH.len;//Смещение на длину пакета, к след. пакету
            F.seekg(sizeof(char)*sme);//Переход указателя в файле
        }

        M.pop_back();//Анти-пуш
        int length=M.size();//Кол-во пакетов
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
        F.close();//Закрываем
    }
}

void MERGE(int a,int b)
{
    for(int i=a;i<=b;i++)
        COPY.push_back(M[i]);//Сохранение в массив копий подотрезка из М
}

bool Comp1(WR A,WR B)
{
    if(A.len==B.len)         //Компоратор сортировки по длине
        return A.num<B.num;
    return A.len<B.len;
}
bool Comp2(WR A,WR B)//Компоратор сортировки по номеру
{
    return A.num<B.num;
}

void Wireshark::on_pushButton_2_clicked()
{
    int START=(ui->lineEdit->text()).toInt()-1;//Начало подотрезка
    int END=(ui->lineEdit_2->text()).toInt()-1;//Конец подотрезка
    ui->textEdit->clear();
    int checker=0;//Проверка кол-ва пакетов(конца подотрезков)
    if(END>M.size())
    {
        END=M.size();
        ui->lineEdit_2->setText(QString::number(M.size()));
    }
    COPY.clear();
    MERGE(START,END);

    if(ui->radioButton->isChecked()==true)
    {
        sort(COPY.begin(),COPY.end(),Comp1);           //Сортировки по номеру и размеру
    }
    else
    {
        sort(COPY.begin(),COPY.end(),Comp2);
    }
    double MED=0;
    int MAX=-1,MIN=-1;
    for(int i=0;i<(int)COPY.size();i++)
    {
        if(checker<=100)                    //Если меньше 100 выводим
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

            INFO="";
            INFO+="Данные Пакета №";
            INFO+=QString::number(COPY[i].num);
            INFO+=":\n\t{";
            for(int j=0;j<COPY[i].D.size();j++)
            {
                if(j%16==0)
                    INFO+="\n\t";
                if(j%8==0 && j%16!=0)
                     INFO+="  ";
                QString Buf=QString::number(COPY[i].D[j],16);
                if(Buf.size()<2)
                    INFO+="0"+Buf;
                else
                    INFO+=Buf;
                INFO+=" ";
            }
            INFO+="\n\t}";
            ui->textEdit_2->append(INFO);
            ui->textEdit_2->append("");
         }
        checker++;
        MED+=COPY[i].len;
        if(MAX<COPY[i].len || MAX==-1)
           MAX=COPY[i].len;                    //Сред. макс. мин.
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
