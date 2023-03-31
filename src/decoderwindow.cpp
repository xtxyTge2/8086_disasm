#include "decoderwindow.h"
#include "./ui_decoderwindow.h"
#include <QFileDialog>
#include <QCommonStyle>

#include "decoder.hpp"

DecoderWindow::DecoderWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::DecoderWindow)
{
    ui->setupUi(this);
    connect(ui->actionOpen_File, &QAction::triggered, this, &DecoderWindow::open);
}

DecoderWindow::~DecoderWindow()
{
    delete ui;
}

void DecoderWindow::open()
{
    inputTextFileName = QFileDialog::getOpenFileName(this,
        tr("Open .asm file to decode"), "", "");
    if(!inputTextFileName.isNull()) {
        QFile file(inputTextFileName);
        file.open(QFile::ReadOnly | QFile::Text);
        ui->inputText->setPlainText(file.readAll());
    }
}


void DecoderWindow::decodeInputText()
{
    std::string inputText = read_entire_file(inputTextFileName.toStdString());
    std::string decodingResult = parse(inputText);

    QString outputText = QString::fromStdString(decodingResult);
    ui->outputText->setPlainText(outputText);
}
