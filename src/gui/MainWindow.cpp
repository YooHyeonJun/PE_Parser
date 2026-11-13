// 메인 창 틀: UI 구성, 파일 열기, 트리 뼈대, 페이지 전환, 테이블/Hex 공통 처리, 오프셋 이동
// 각 페이지 내용은 HeaderPages.cpp / SectionPages.cpp / DirectoryPages.cpp 에 있다.
#include "gui/MainWindow.h"

#include "gui/GuiCommon.h"
#include "gui/HexView.h"

#include <QApplication>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QFileDialog>
#include <QFileInfo>
#include <QFontDatabase>
#include <QHeaderView>
#include <QLabel>
#include <QMenuBar>
#include <QMessageBox>
#include <QMimeData>
#include <QSplitter>
#include <QStackedWidget>
#include <QStatusBar>
#include <QTableWidget>
#include <QTreeWidget>
#include <QTreeWidgetItemIterator>
#include <QVBoxLayout>

using namespace gui;

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
    setupUi();
}

MainWindow::~MainWindow() = default;

void MainWindow::setupUi() {
    setWindowTitle(tr("PE Parser"));
    resize(1100, 700);
    setAcceptDrops(true);

    // 메뉴
    auto* fileMenu = menuBar()->addMenu(tr("&File"));
    fileMenu->addAction(tr("&Open..."), QKeySequence::Open, this, &MainWindow::onOpen);
    fileMenu->addSeparator();
    fileMenu->addAction(tr("E&xit"), QKeySequence::Quit, qApp, &QApplication::quit);

    // 좌: 구조 트리 / 우: 필드 테이블
    tree_ = new QTreeWidget(this);
    tree_->setHeaderLabel(tr("Structure"));
    connect(tree_, &QTreeWidget::itemSelectionChanged, this, &MainWindow::onTreeSelectionChanged);

    table_ = new QTableWidget(this);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setAlternatingRowColors(true);
    table_->verticalHeader()->setVisible(false);
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    connect(table_, &QTableWidget::cellDoubleClicked, this, &MainWindow::onTableDoubleClicked);

    hexView_ = new HexView(this);

    stack_ = new QStackedWidget(this);
    stack_->addWidget(table_);
    stack_->addWidget(hexView_);

    // 우측 = [요약 라벨] + [테이블 | Hex 뷰]
    pageInfo_ = new QLabel(this);
    pageInfo_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    pageInfo_->setWordWrap(true);
    pageInfo_->setContentsMargins(6, 4, 6, 4);
    pageInfo_->hide();

    auto* right = new QWidget(this);
    auto* rightLayout = new QVBoxLayout(right);
    rightLayout->setContentsMargins(0, 0, 0, 0);
    rightLayout->setSpacing(2);
    rightLayout->addWidget(pageInfo_);
    rightLayout->addWidget(stack_, 1);

    auto* splitter = new QSplitter(this);
    splitter->addWidget(tree_);
    splitter->addWidget(right);
    splitter->setStretchFactor(1, 1);
    splitter->setSizes({260, 840});
    setCentralWidget(splitter);

    statusLabel_ = new QLabel(tr("파일을 열거나 창에 드래그하세요."), this);
    statusBar()->addWidget(statusLabel_, 1);
}

// ---------------------------------------------------------------------------
// 파일 열기
// ---------------------------------------------------------------------------

void MainWindow::onOpen() {
    const QString path = QFileDialog::getOpenFileName(
        this, tr("PE 파일 열기"), {}, tr("PE Files (*.exe *.dll *.sys *.ocx *.scr *.cpl *.efi);;All Files (*)"));
    if (!path.isEmpty()) openFile(path);
}

bool MainWindow::openFile(const QString& path) {
    auto pe = std::make_unique<pe::PeFile>();
    if (!pe->load(path.toStdWString())) {
        QMessageBox::warning(this, tr("파싱 실패"),
                             tr("%1\n\n%2").arg(path, QString::fromStdString(pe->error())));
        return false;
    }

    // Hex 모델이 이전 파일 버퍼를 가리키지 않도록 먼저 비운다 (pe_ 교체 시 버퍼 해제됨)
    hexView_->hexModel()->setBytes(nullptr, 0, 0, std::nullopt, {});
    pe_ = std::move(pe);
    currentPath_ = path;
    setWindowTitle(tr("PE Parser - %1").arg(QFileInfo(path).fileName()));
    statusLabel_->setText(tr("%1  |  %2  |  %3 bytes")
                              .arg(path, pe_->is64() ? "PE32+" : "PE32")
                              .arg(pe_->raw().size()));
    buildTree();
    return true;
}

void MainWindow::dragEnterEvent(QDragEnterEvent* e) {
    if (e->mimeData()->hasUrls()) e->acceptProposedAction();
}

void MainWindow::dropEvent(QDropEvent* e) {
    const auto urls = e->mimeData()->urls();
    if (!urls.isEmpty() && urls.first().isLocalFile()) openFile(urls.first().toLocalFile());
}

// ---------------------------------------------------------------------------
// 트리
// ---------------------------------------------------------------------------

QTreeWidgetItem* MainWindow::makeTreeItem(QTreeWidgetItem* parent, const QString& text, Page page, int index) {
    auto* item = new QTreeWidgetItem(parent, {text});
    item->setData(0, kRolePage, static_cast<int>(page));
    item->setData(0, kRoleIndex, index);
    return item;
}

void MainWindow::buildTree() {
    tree_->clear();

    // 루트 = 파일 전체 hex
    fileDataItem_ = new QTreeWidgetItem(tree_, {QFileInfo(currentPath_).fileName()});
    fileDataItem_->setData(0, kRolePage, static_cast<int>(Page::FileData));
    fileDataItem_->setData(0, kRoleIndex, -1);

    buildHeaderNodes(fileDataItem_);   // IMAGE_DOS_HEADER ~ IMAGE_SECTION_HEADER
    buildSectionNodes(fileDataItem_);  // SECTION .xxx + 섹션 안의 구조

    tree_->expandAll();
    // IMPORT Directory Table 의 DLL 목록은 길어서 접어 둔다 (펼치면 DLL 별 함수 표)
    for (QTreeWidgetItemIterator it(tree_); *it; ++it)
        if ((*it)->data(0, kRolePage).toInt() == static_cast<int>(Page::Imports)) (*it)->setExpanded(false);
    tree_->setCurrentItem(fileDataItem_->child(0));
}

void MainWindow::onTreeSelectionChanged() {
    auto* item = tree_->currentItem();
    if (!pe_ || !item || !item->data(0, kRolePage).isValid()) return;
    showPage(static_cast<Page>(item->data(0, kRolePage).toInt()), item->data(0, kRoleIndex).toInt());
}

void MainWindow::showPage(Page page, int index) {
    switch (page) {
        // 헤더
        case Page::DosHeader: showDosHeader(); break;
        case Page::DosStub: showDosStub(); break;
        case Page::NtHeaders: showNtHeaders(); break;
        case Page::FileHeader: showFileHeader(); break;
        case Page::OptionalHeader: showOptionalHeader(); break;
        case Page::DataDirectories: showDataDirectories(); break;
        case Page::Section: showSection(index); break;
        // Import / Export
        case Page::Imports: showImports(); break;
        case Page::ImportModule: showImportModule(index); break;
        case Page::ImportAddressTable: showImportThunks(true); break;
        case Page::ImportNameTable: showImportThunks(false); break;
        case Page::ImportHintNames: showImportHintNames(); break;
        case Page::ExportDirectory: showExportDirectory(); break;
        case Page::ExportFunctions: showExportFunctions(); break;
        case Page::ExportNameTable: showExportNameTable(); break;
        case Page::ExportOrdinalTable: showExportOrdinalTable(); break;
        case Page::ExportNames: showExportNames(); break;
        case Page::RelocBlocks: showRelocBlocks(); break;
        case Page::RelocBlock: showRelocBlock(index); break;
        // Hex 뷰
        case Page::FileData: showFileData(); return;
        case Page::SectionData: showSectionData(index); return;
        case Page::DirectoryData: showDirectoryData(index); return;
    }
    table_->resizeColumnsToContents();
}

// ---------------------------------------------------------------------------
// 테이블 공통
// ---------------------------------------------------------------------------

void MainWindow::clearTable(const QStringList& headers) {
    table_->clear();
    table_->setRowCount(0);
    table_->setColumnCount(headers.size());
    table_->setHorizontalHeaderLabels(headers);
    stack_->setCurrentWidget(table_);
    pageInfo_->clear();
    pageInfo_->hide();
}

void MainWindow::setPageInfo(const QString& text) {
    pageInfo_->setText(text);
    pageInfo_->setVisible(!text.isEmpty());
}

void MainWindow::addRow(const QString& field, uint64_t offset, size_t size, uint64_t value, const QString& desc) {
    // 가상 위치(파일에 없음)는 "(virtual)" 표시 + 더블클릭 이동 없음
    addRowText({offStr(offset), field, QString::number(size), hex(value, static_cast<int>(size * 2)), desc},
               isVirtualOffset(offset) ? kNoJump : offset, size);
}

void MainWindow::addRowText(const QStringList& cells, uint64_t jumpOffset, uint64_t jumpSize) {
    const int row = table_->rowCount();
    table_->insertRow(row);
    for (int c = 0; c < cells.size(); ++c) table_->setItem(row, c, new QTableWidgetItem(cells[c]));

    if (jumpOffset != kNoJump && table_->item(row, 0)) {
        auto* first = table_->item(row, 0);
        first->setData(kRoleJumpOffset, static_cast<qulonglong>(jumpOffset));
        first->setData(kRoleJumpSize, static_cast<qulonglong>(jumpSize));
        first->setToolTip(tr("더블클릭: Hex 뷰에서 %1 보기").arg(hex(jumpOffset, 8)));
    }
}

void MainWindow::onTableDoubleClicked(int row, int /*column*/) {
    auto* item = table_->item(row, 0);
    if (!item || !item->data(kRoleJumpOffset).isValid()) return;
    jumpToOffset(item->data(kRoleJumpOffset).toULongLong(), item->data(kRoleJumpSize).toULongLong());
}

// ---------------------------------------------------------------------------
// Hex 뷰 공통
// ---------------------------------------------------------------------------

void MainWindow::showHex(uint64_t fileOffset, size_t size, std::optional<int64_t> rvaDelta,
                         std::vector<HexRegion> regions, const QString& infoHtml) {
    pageInfo_->clear();
    const auto& raw = pe_->raw();
    if (fileOffset >= raw.size()) size = 0;
    size = static_cast<size_t>(std::min<uint64_t>(size, raw.size() - std::min<uint64_t>(fileOffset, raw.size())));

    hexView_->hexModel()->setBytes(size ? raw.data() + fileOffset : nullptr, size, fileOffset, rvaDelta,
                                   std::move(regions));
    stack_->setCurrentWidget(hexView_);
    setPageInfo(infoHtml);
    hexView_->scrollToTop();
}

void MainWindow::showFileData() {
    // 파일 전체 (가상 모델이라 대용량도 즉시 표시). RVA 열은 위치마다 다르므로 비움
    const uint64_t size = pe_->raw().size();
    auto regions = headerRegions();
    for (auto& r : parsedRegionsIn(0, size)) regions.push_back(std::move(r));

    // 섹션 경계 안내
    QString secs;
    for (const auto& s : pe_->sections()) {
        if (s.SizeOfRawData == 0) continue;
        secs += QString("%1 %2 &nbsp; ").arg(QString::fromStdString(pe::sectionName(s)).toHtmlEscaped(),
                                              hex(s.PointerToRawData, 8));
    }

    std::vector<std::pair<QString, QColor>> legend;
    for (const auto& r : headerRegions()) legend.push_back({r.label, r.color});

    const QString info = tr("<b>%1</b> &nbsp; 파일 전체 %2 bytes<br>섹션 시작: %3<br>%4")
                             .arg(QFileInfo(currentPath_).fileName().toHtmlEscaped())
                             .arg(size)
                             .arg(secs, legendHtml(legend));
    showHex(0, static_cast<size_t>(size), std::nullopt, std::move(regions), info);
}

void MainWindow::jumpToOffset(uint64_t off, uint64_t size) {
    // 섹션 안이면 SECTION 노드, 아니면(헤더 / Overlay) 루트(파일 전체)
    QTreeWidgetItem* target = fileDataItem_;
    if (auto idx = pe_->sectionIndexForOffset(off); idx && *idx < sectionDataItems_.size())
        target = sectionDataItems_[*idx];

    if (!target || off >= pe_->raw().size()) {
        statusBar()->showMessage(tr("%1 은(는) 파일 범위 밖입니다.").arg(hex(off, 8)), 5000);
        return;
    }
    if (tree_->currentItem() != target) tree_->setCurrentItem(target);  // → showSectionData / showFileData
    hexView_->selectRange(off, size);
}
