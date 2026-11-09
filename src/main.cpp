#include "gui/MainWindow.h"

#include <QApplication>

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    QApplication::setApplicationName("PE Parser");

    MainWindow w;
    w.show();

    // 커맨드라인 인자로 파일 경로가 오면 바로 연다 (탐색기 "연결 프로그램" 대비)
    const QStringList args = QApplication::arguments();
    if (args.size() > 1) w.openFile(args.at(1));

    return app.exec();
}
