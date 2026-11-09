#include "gui/MainWindow.h"

#include <QApplication>
#include <QDateTime>
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
#include <QStatusBar>
#include <QTableWidget>
#include <QTreeWidget>

#include <type_traits>

namespace {
constexpr int kRolePage = Qt::UserRole;
constexpr int kRoleIndex = Qt::UserRole + 1;

QString hex(uint64_t v, int width) {
    return QStringLiteral("0x%1").arg(v, width, 16, QLatin1Char('0')).toUpper().replace("0X", "0x");
}
}  // namespace

// 구조체 멤버 하나를 (이름, 파일오프셋, 크기, 값) 으로 테이블에 추가
#define ADD_FIELD(base, s, member, ...)                                                              \
    addRow(QStringLiteral(#member), (base) + offsetof(std::remove_cvref_t<decltype(s)>, member),    \
           sizeof((s).member), static_cast<uint64_t>((s).member), ##__VA_ARGS__)

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

    auto* splitter = new QSplitter(this);
    splitter->addWidget(tree_);
    splitter->addWidget(table_);
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

void MainWindow::buildTree() {
    tree_->clear();

    auto makeItem = [](QTreeWidgetItem* parent, const QString& text, Page page, int index = -1) {
        auto* item = new QTreeWidgetItem(parent, {text});
        item->setData(0, kRolePage, static_cast<int>(page));
        item->setData(0, kRoleIndex, index);
        return item;
    };

    auto* root = new QTreeWidgetItem(tree_, {QFileInfo(currentPath_).fileName()});
    makeItem(root, "IMAGE_DOS_HEADER", Page::DosHeader);
    auto* nt = makeItem(root, "IMAGE_NT_HEADERS", Page::NtHeaders);
    makeItem(nt, "IMAGE_FILE_HEADER", Page::FileHeader);
    auto* opt = makeItem(nt, "IMAGE_OPTIONAL_HEADER", Page::OptionalHeader);
    makeItem(opt, "Data Directories", Page::DataDirectories);
    auto* secs = makeItem(root, "Section Headers", Page::SectionTable);
    const auto& sections = pe_->sections();
    for (int i = 0; i < static_cast<int>(sections.size()); ++i)
        makeItem(secs, QString::fromStdString(pe::sectionName(sections[i])), Page::Section, i);

    tree_->expandAll();
    tree_->setCurrentItem(root->child(0));
}

void MainWindow::onTreeSelectionChanged() {
    auto* item = tree_->currentItem();
    if (!pe_ || !item || !item->data(0, kRolePage).isValid()) return;
    showPage(static_cast<Page>(item->data(0, kRolePage).toInt()), item->data(0, kRoleIndex).toInt());
}

void MainWindow::showPage(Page page, int index) {
    switch (page) {
        case Page::DosHeader: showDosHeader(); break;
        case Page::NtHeaders: showNtHeaders(); break;
        case Page::FileHeader: showFileHeader(); break;
        case Page::OptionalHeader: showOptionalHeader(); break;
        case Page::DataDirectories: showDataDirectories(); break;
        case Page::SectionTable: showSectionTable(); break;
        case Page::Section: showSection(index); break;
    }
    table_->resizeColumnsToContents();
}

// ---------------------------------------------------------------------------
// 테이블 헬퍼
// ---------------------------------------------------------------------------

void MainWindow::clearTable(const QStringList& headers) {
    table_->clear();
    table_->setRowCount(0);
    table_->setColumnCount(headers.size());
    table_->setHorizontalHeaderLabels(headers);
}

void MainWindow::addRow(const QString& field, uint64_t offset, size_t size, uint64_t value, const QString& desc) {
    addRowText({field, hex(offset, 8), QString::number(size), hex(value, static_cast<int>(size * 2)), desc});
}

void MainWindow::addRowText(const QStringList& cells) {
    const int row = table_->rowCount();
    table_->insertRow(row);
    for (int c = 0; c < cells.size(); ++c) table_->setItem(row, c, new QTableWidgetItem(cells[c]));
}

static const QStringList kFieldHeaders = {"Field", "Offset", "Size", "Value", "Description"};

// ---------------------------------------------------------------------------
// 각 페이지
// ---------------------------------------------------------------------------

void MainWindow::showDosHeader() {
    clearTable(kFieldHeaders);
    const auto& d = pe_->dosHeader();
    constexpr uint64_t b = 0;
    ADD_FIELD(b, d, e_magic, "MZ");
    ADD_FIELD(b, d, e_cblp);
    ADD_FIELD(b, d, e_cp);
    ADD_FIELD(b, d, e_crlc);
    ADD_FIELD(b, d, e_cparhdr);
    ADD_FIELD(b, d, e_minalloc);
    ADD_FIELD(b, d, e_maxalloc);
    ADD_FIELD(b, d, e_ss);
    ADD_FIELD(b, d, e_sp);
    ADD_FIELD(b, d, e_csum);
    ADD_FIELD(b, d, e_ip);
    ADD_FIELD(b, d, e_cs);
    ADD_FIELD(b, d, e_lfarlc);
    ADD_FIELD(b, d, e_ovno);
    ADD_FIELD(b, d, e_oemid);
    ADD_FIELD(b, d, e_oeminfo);
    ADD_FIELD(b, d, e_lfanew, tr("NT Headers 오프셋"));
}

void MainWindow::showNtHeaders() {
    clearTable(kFieldHeaders);
    addRow("Signature", pe_->ntHeadersOffset(), 4, pe_->ntSignature(), "PE\\0\\0");
}

void MainWindow::showFileHeader() {
    clearTable(kFieldHeaders);
    const auto& f = pe_->fileHeader();
    const uint64_t b = pe_->fileHeaderOffset();
    ADD_FIELD(b, f, Machine, pe::machineToString(f.Machine));
    ADD_FIELD(b, f, NumberOfSections);
    ADD_FIELD(b, f, TimeDateStamp,
              QDateTime::fromSecsSinceEpoch(f.TimeDateStamp, QTimeZone::UTC).toString("yyyy-MM-dd hh:mm:ss UTC"));
    ADD_FIELD(b, f, PointerToSymbolTable);
    ADD_FIELD(b, f, NumberOfSymbols);
    ADD_FIELD(b, f, SizeOfOptionalHeader);
    ADD_FIELD(b, f, Characteristics, QString::fromStdString(pe::fileCharacteristicsToString(f.Characteristics)));
}

void MainWindow::showOptionalHeader() {
    clearTable(kFieldHeaders);
    const uint64_t b = pe_->optionalHeaderOffset();

    // PE32 / PE32+ 의 필드 이름이 같으므로 제네릭 람다로 한 번에 처리
    auto fill = [&](const auto& o) {
        ADD_FIELD(b, o, Magic, pe_->is64() ? "PE32+" : "PE32");
        ADD_FIELD(b, o, MajorLinkerVersion);
        ADD_FIELD(b, o, MinorLinkerVersion);
        ADD_FIELD(b, o, SizeOfCode);
        ADD_FIELD(b, o, SizeOfInitializedData);
        ADD_FIELD(b, o, SizeOfUninitializedData);
        ADD_FIELD(b, o, AddressOfEntryPoint, tr("RVA"));
        ADD_FIELD(b, o, BaseOfCode);
        if constexpr (std::is_same_v<std::remove_cvref_t<decltype(o)>, pe::OptionalHeader32>)
            ADD_FIELD(b, o, BaseOfData);
        ADD_FIELD(b, o, ImageBase);
        ADD_FIELD(b, o, SectionAlignment);
        ADD_FIELD(b, o, FileAlignment);
        ADD_FIELD(b, o, MajorOperatingSystemVersion);
        ADD_FIELD(b, o, MinorOperatingSystemVersion);
        ADD_FIELD(b, o, MajorImageVersion);
        ADD_FIELD(b, o, MinorImageVersion);
        ADD_FIELD(b, o, MajorSubsystemVersion);
        ADD_FIELD(b, o, MinorSubsystemVersion);
        ADD_FIELD(b, o, Win32VersionValue);
        ADD_FIELD(b, o, SizeOfImage);
        ADD_FIELD(b, o, SizeOfHeaders);
        ADD_FIELD(b, o, CheckSum);
        ADD_FIELD(b, o, Subsystem, pe::subsystemToString(o.Subsystem));
        ADD_FIELD(b, o, DllCharacteristics);
        ADD_FIELD(b, o, SizeOfStackReserve);
        ADD_FIELD(b, o, SizeOfStackCommit);
        ADD_FIELD(b, o, SizeOfHeapReserve);
        ADD_FIELD(b, o, SizeOfHeapCommit);
        ADD_FIELD(b, o, LoaderFlags);
        ADD_FIELD(b, o, NumberOfRvaAndSizes);
    };
    if (pe_->is64())
        fill(pe_->optionalHeader64());
    else
        fill(pe_->optionalHeader32());
}

void MainWindow::showDataDirectories() {
    clearTable({"Directory", "Offset", "RVA", "Size", "File Offset"});
    const auto& dirs = pe_->dataDirectories();
    for (size_t i = 0; i < dirs.size(); ++i) {
        const auto& d = dirs[i];
        QString fileOff = "-";
        if (d.VirtualAddress != 0) {
            // Security 디렉터리는 예외적으로 RVA가 아니라 파일 오프셋이다
            if (i == 4)
                fileOff = hex(d.VirtualAddress, 8);
            else if (auto off = pe_->rvaToOffset(d.VirtualAddress))
                fileOff = hex(*off, 8);
            else
                fileOff = tr("(매핑 불가)");
        }
        addRowText({pe::dataDirectoryName(i), hex(pe_->dataDirectoriesOffset() + i * sizeof(pe::DataDirectory), 8),
                    hex(d.VirtualAddress, 8), hex(d.Size, 8), fileOff});
    }
}

void MainWindow::showSectionTable() {
    clearTable({"Name", "VirtualSize", "VirtualAddress", "SizeOfRawData", "PointerToRawData", "Characteristics", "Flags"});
    for (const auto& s : pe_->sections()) {
        addRowText({QString::fromStdString(pe::sectionName(s)), hex(s.VirtualSize, 8), hex(s.VirtualAddress, 8),
                    hex(s.SizeOfRawData, 8), hex(s.PointerToRawData, 8), hex(s.Characteristics, 8),
                    QString::fromStdString(pe::sectionCharacteristicsToString(s.Characteristics))});
    }
}

void MainWindow::showSection(int index) {
    clearTable(kFieldHeaders);
    const auto& secs = pe_->sections();
    if (index < 0 || index >= static_cast<int>(secs.size())) return;
    const auto& s = secs[index];
    const uint64_t b = pe_->sectionTableOffset() + index * sizeof(pe::SectionHeader);

    addRowText({"Name", hex(b, 8), "8", QString::fromStdString(pe::sectionName(s)), {}});
    ADD_FIELD(b, s, VirtualSize);
    ADD_FIELD(b, s, VirtualAddress);
    ADD_FIELD(b, s, SizeOfRawData);
    ADD_FIELD(b, s, PointerToRawData);
    ADD_FIELD(b, s, PointerToRelocations);
    ADD_FIELD(b, s, PointerToLinenumbers);
    ADD_FIELD(b, s, NumberOfRelocations);
    ADD_FIELD(b, s, NumberOfLinenumbers);
    ADD_FIELD(b, s, Characteristics, QString::fromStdString(pe::sectionCharacteristicsToString(s.Characteristics)));
}
