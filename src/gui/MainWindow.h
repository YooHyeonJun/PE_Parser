#pragma once

#include "core/PeFile.h"

#include <QMainWindow>

#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <vector>

class QTreeWidget;
class QTreeWidgetItem;
class QTableWidget;
class QLabel;
class QStackedWidget;
class HexView;
struct HexRegion;

// 메인 창. 구현은 역할별 파일로 나뉜다:
//   MainWindow.cpp     창 틀, 파일 열기, 트리 뼈대, 테이블/Hex 공통 처리, 오프셋 이동
//   HeaderPages.cpp    헤더 노드와 화면 (DOS / Stub / NT / File / Optional / Data Directories / Section Header)
//   SectionPages.cpp   SECTION 노드와 섹션 hex, 섹션 안 구조 노드 배치, 미파싱 디렉터리 hex
//   DirectoryPages.cpp Import / Export 화면
//   TlsPages.cpp       TLS 화면
//   RelocPages.cpp     Base Relocation 화면
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
    void onTableDoubleClicked(int row, int column);

private:
    // 트리 노드가 가리키는 화면 종류
    // (PEView 스타일: 루트=파일 전체 hex, SECTION 노드=섹션 hex, 그 아래에 섹션 안의 구조들)
    enum class Page {
        // 헤더 (HeaderPages.cpp)
        DosHeader, DosStub, NtHeaders, FileHeader, OptionalHeader, DataDirectories, Section,
        // Import / Export (DirectoryPages.cpp)
        Imports, ImportModule, ImportAddressTable, ImportNameTable, ImportHintNames,
        ExportDirectory, ExportFunctions, ExportNameTable, ExportOrdinalTable, ExportNames,
        // TLS (TlsPages.cpp)
        TlsDirectory, TlsCallbacks,
        // Base Relocation (RelocPages.cpp)
        RelocBlocks, RelocBlock,
        // Hex 뷰 (MainWindow.cpp / SectionPages.cpp)
        FileData, SectionData, DirectoryData
    };

    static constexpr uint64_t kNoJump = std::numeric_limits<uint64_t>::max();

    // ======================================================================
    // 공통 (MainWindow.cpp)
    // ======================================================================
    void setupUi();
    void buildTree();
    QTreeWidgetItem* makeTreeItem(QTreeWidgetItem* parent, const QString& text, Page page, int index = -1);
    void showPage(Page page, int index);

    // 테이블
    void clearTable(const QStringList& headers);
    void addRow(const QString& field, uint64_t offset, size_t size, uint64_t value, const QString& desc = {});
    // jumpOffset: 이 행을 더블클릭하면 Hex 뷰에서 [jumpOffset, +jumpSize) 를 보여준다
    void addRowText(const QStringList& cells, uint64_t jumpOffset = kNoJump, uint64_t jumpSize = 0);
    void setPageInfo(const QString& text);  // 테이블 위 요약 라벨 (clearTable 시 자동 숨김)

    // Hex 뷰
    void showHex(uint64_t fileOffset, size_t size, std::optional<int64_t> rvaDelta, std::vector<HexRegion> regions,
                 const QString& infoHtml);
    void showFileData();  // 루트: 파일 전체
    void jumpToOffset(uint64_t fileOffset, uint64_t size);

    // ======================================================================
    // 헤더 (HeaderPages.cpp)
    // ======================================================================
    void buildHeaderNodes(QTreeWidgetItem* root);  // DOS ~ IMAGE_SECTION_HEADER 노드
    void showDosHeader();
    void showDosStub();
    void showNtHeaders();
    void showFileHeader();
    void showOptionalHeader();
    void showDataDirectories();
    void showSection(int index);                    // IMAGE_SECTION_HEADER 필드
    std::vector<HexRegion> headerRegions() const;  // 헤더 구조 색 구간 (파일 전체 hex 용)

    // ======================================================================
    // 섹션 (SectionPages.cpp)
    // ======================================================================
    void buildSectionNodes(QTreeWidgetItem* root);  // SECTION 노드 + 그 안의 구조 노드
    void showSectionData(int index);
    void showDirectoryData(int dirIndex);  // 아직 파싱하지 않은 디렉터리의 원본 바이트
    std::vector<HexRegion> parsedRegionsIn(uint64_t begin, uint64_t end) const;
    QStringList directoriesInSection(size_t sectionIndex) const;
    std::optional<uint64_t> directoryFileOffset(size_t dirIndex) const;

    // ======================================================================
    // Import / Export (DirectoryPages.cpp)
    // ======================================================================
    void showImports();
    void showImportModule(int index);
    void showImportThunks(bool iat);  // IMPORT Address Table / IMPORT Name Table
    void showImportHintNames();
    void showExportDirectory();
    void showExportFunctions();
    void showExportNameTable();
    void showExportOrdinalTable();
    void showExportNames();

    // ======================================================================
    // TLS (TlsPages.cpp)
    // ======================================================================
    void showTlsDirectory();
    void showTlsCallbacks();

    // ======================================================================
    // Base Relocation (RelocPages.cpp)
    // ======================================================================
    void showRelocBlocks();          // 블록 목록
    void showRelocBlock(int index);  // 블록 하나의 항목들

    // ======================================================================
    // 상태
    // ======================================================================
    QTreeWidget* tree_ = nullptr;
    QStackedWidget* stack_ = nullptr;  // table_ / hexView_ 전환
    QTableWidget* table_ = nullptr;
    HexView* hexView_ = nullptr;
    QTreeWidgetItem* fileDataItem_ = nullptr;         // 루트 (파일 전체 hex)
    std::vector<QTreeWidgetItem*> sectionDataItems_;  // SECTION .xxx (섹션 hex)
    QLabel* pageInfo_ = nullptr;
    QLabel* statusLabel_ = nullptr;

    std::unique_ptr<pe::PeFile> pe_;
    QString currentPath_;
};
