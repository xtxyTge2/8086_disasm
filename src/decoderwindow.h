#ifndef DECODERWINDOW_H
#define DECODERWINDOW_H

#include <QMainWindow>

QT_BEGIN_NAMESPACE
namespace Ui { class DecoderWindow; }
QT_END_NAMESPACE

class DecoderWindow : public QMainWindow
{
    Q_OBJECT

public:
    DecoderWindow(QWidget *parent = nullptr);
    ~DecoderWindow();

private slots:
    void openInputFile();
    void openSolutionFile();
    void decodeInputText();

private:
    Ui::DecoderWindow *ui;
    QString inputTextFileName;
    QString solutionTextFileName;
};
#endif // DECODERWINDOW_H
