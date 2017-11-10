#ifndef WIRESHARK_H
#define WIRESHARK_H
#include <QFileDialog>
#include <QString>
#include <QMainWindow>
#include <fstream>
#include <vector>
#include <algorithm>
namespace Ui {
class Wireshark;
}

class Wireshark : public QDialog
{
    Q_OBJECT

public:
    explicit Wireshark(QWidget *parent = 0);
    ~Wireshark();

private slots:
    void on_pushButton_clicked();

    void on_pushButton_2_clicked();

private:
    Ui::Wireshark *ui;
};

struct PackHead {
    unsigned long a;
    unsigned long b;
    unsigned int caplen;
    unsigned int len;
};

#endif // WIRESHARK_H
