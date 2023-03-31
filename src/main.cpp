#include "decoderwindow.h"

#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    DecoderWindow w;
    w.show();
    return a.exec();
}
