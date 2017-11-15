#ifndef CAL_H
#define CAL_H

#include <QDialog>

namespace Ui {
class Cal;
}

class Cal : public QDialog
{
    Q_OBJECT

public:
    explicit Cal(QWidget *parent = 0);
    ~Cal();

private:
    Ui::Cal *ui;

private slots:
    void digit_pressed();
    void on_pushButton_tochka_released();
    void unary_operation_pressed();
    void on_pushButton_clear_released();
    void on_pushButton_ravno_released();
    void binary_operation_pressed();

};

#endif // CAL_H\
