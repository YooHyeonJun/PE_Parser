#pragma once

#include "core/PeFile.h"

#include <QMainWindow>

#include <memory>

class QTreeWidget;
class QTreeWidgetItem;
class QTableWidget;
class QLabel;

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;

    bool openFile(const QString& path);

protected:
    void dragEnterEvent(QDragEnterEvent* e) override;
    void dropEvent(QDropEvent* e) override;

private slots:
    void onOpen();
    void onTreeSelectionChanged();

private:
    // 트리 노드가 가리키는 화면 종류
    enum class Page { DosHeader, NtHeaders, FileHeader, OptionalHeader, DataDirectories, SectionTable, Section };

    void setupUi();
    void buildTree();
    void showPage(Page page, int index);

    // 테이블 채우기 헬퍼
    void clearTable(const QStringList& headers);
    void addRow(const QString& field, uint64_t offset, size_t size, uint64_t value, const QString& desc = {});
    void addRowText(const QStringList& cells);

    void showDosHeader();
    void showNtHeaders();
    void showFileHeader();
    void showOptionalHeader();
    void showDataDirectories();
    void showSectionTable();
    void showSection(int index);

    QTreeWidget* tree_ = nullptr;
    QTableWidget* table_ = nullptr;
    QLabel* statusLabel_ = nullptr;

    std::unique_ptr<pe::PeFile> pe_;
    QString currentPath_;
};
