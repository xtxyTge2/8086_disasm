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
    connect(ui->actionOpen_File, &QAction::triggered, this, &DecoderWindow::openInputFile);
    connect(ui->actionOpen_Solution_File, &QAction::triggered, this, &DecoderWindow::openSolutionFile);
}

DecoderWindow::~DecoderWindow()
{
    delete ui;
}

void DecoderWindow::openInputFile()
{
    inputTextFileName = QFileDialog::getOpenFileName(this,
        tr("Open .asm file to decode"), "", "");
    if(!inputTextFileName.isNull()) {
        QFile inputTextFile(inputTextFileName);
        inputTextFile.open(QFile::ReadOnly | QFile::Text);
        ui->inputText->setPlainText(inputTextFile.readAll());
    }

    ui->outputText->setPlainText("");
}

void DecoderWindow::openSolutionFile()
{
    solutionTextFileName = QFileDialog::getOpenFileName(this,
                                                     tr("Open .asm file to decode"), "", "");
    if(!solutionTextFileName.isNull()) {
        QFile solutionTextFile(solutionTextFileName);
        solutionTextFile.open(QFile::ReadOnly | QFile::Text);
        ui->solutionText->setPlainText(solutionTextFile.readAll());
    }
}


void DecoderWindow::decodeInputText()
{
    std::string inputText = read_entire_file(inputTextFileName.toStdString());
    std::unique_ptr<Decoder> p_decoder = std::make_unique<Decoder>();
    DecodingResult decoding_result = p_decoder->try_to_parse_input_stream(inputText);

    QString outputText = QString::fromStdString(decoding_result.to_string());
    ui->outputText->setPlainText(outputText);
}
