// 헤더 화면: 트리의 헤더 노드 + DOS Header / DOS Stub / NT Headers / File Header / Optional Header /
//            Data Directories / IMAGE_SECTION_HEADER 필드 테이블, 파일 전체 hex 의 헤더 색 구간
#include "gui/GuiCommon.h"
#include "gui/HexView.h"
#include "gui/MainWindow.h"

#include <QDateTime>
#include <QTableWidget>
#include <QTimeZone>
#include <QTreeWidget>

using namespace gui;

// ---------------------------------------------------------------------------
// 트리
// ---------------------------------------------------------------------------

void MainWindow::buildHeaderNodes(QTreeWidgetItem* root) {
    makeTreeItem(root, "IMAGE_DOS_HEADER", Page::DosHeader);
    makeTreeItem(root, "MS-DOS Stub Program", Page::DosStub);
    auto* nt = makeTreeItem(root, "IMAGE_NT_HEADERS", Page::NtHeaders);
    makeTreeItem(nt, "IMAGE_FILE_HEADER", Page::FileHeader);
    auto* opt = makeTreeItem(nt, "IMAGE_OPTIONAL_HEADER", Page::OptionalHeader);
    makeTreeItem(opt, QString("Data Directories (%1)").arg(static_cast<qulonglong>(pe_->dataDirectories().size())),
                 Page::DataDirectories);

    // IMAGE_SECTION_HEADER .xxx (섹션 헤더 = 헤더 영역의 Section Table 항목)
    const auto& sections = pe_->sections();
    for (int i = 0; i < static_cast<int>(sections.size()); ++i)
        makeTreeItem(root, "IMAGE_SECTION_HEADER " + QString::fromStdString(pe::sectionName(sections[i])),
                     Page::Section, i);
}

// ---------------------------------------------------------------------------
// 페이지
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

void MainWindow::showDosStub() {
    clearTable({"File Offset", "Hex", "ASCII"});

    const auto stub = pe_->dosStub();
    const uint64_t base = pe_->dosStubOffset();
    const std::string msg = pe_->dosStubMessage();

    // 상단 요약
    QString info = tr("Offset: %1    Size: %2 bytes (0x%3)")
                       .arg(hex(base, 8))
                       .arg(static_cast<qulonglong>(stub.size()))
                       .arg(static_cast<qulonglong>(stub.size()), 0, 16);
    info += "\n" + tr("Message: %1").arg(msg.empty() ? tr("(없음)") : QString::fromStdString(msg));
    if (stub.empty()) info += "\n" + tr("DOS Stub이 없습니다 (e_lfanew <= 0x40).");

    // Hex 덤프 (16바이트/행). e_lfanew 를 비정상적으로 크게 잡은 파일 대비 64KB 까지만 표시
    constexpr size_t kBytesPerRow = 16;
    constexpr size_t kMaxRows = 4096;
    const size_t totalRows = (stub.size() + kBytesPerRow - 1) / kBytesPerRow;
    const size_t rows = std::min(totalRows, kMaxRows);
    if (rows < totalRows) info += "\n" + tr("(처음 %1 바이트만 표시)").arg(rows * kBytesPerRow);
    setPageInfo(info);

    table_->setUpdatesEnabled(false);
    for (size_t r = 0; r < rows; ++r) {
        QString hexStr, ascii;
        const size_t begin = r * kBytesPerRow;
        const size_t end = std::min(begin + kBytesPerRow, stub.size());
        for (size_t i = begin; i < end; ++i) {
            const uint8_t b = stub[i];
            hexStr += QStringLiteral("%1 ").arg(static_cast<uint>(b), 2, 16, QLatin1Char('0')).toUpper();
            if (i - begin == 7) hexStr += ' ';  // 8바이트마다 구분
            ascii += (b >= 0x20 && b < 0x7F) ? QChar(b) : QChar('.');
        }
        addRowText({hex(base + begin, 8), hexStr.trimmed(), ascii}, base + begin, end - begin);
    }
    table_->setUpdatesEnabled(true);
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
    // File Offset = 디렉터리 엔트리(8바이트) 위치, Data Offset = RVA 가 가리키는 실제 데이터의 파일 위치
    clearTable({"File Offset", "#", "Directory", "RVA", "Size", "Data Offset"});
    const auto& dirs = pe_->dataDirectories();

    QString info = tr("Count: %1 (NumberOfRvaAndSizes)").arg(static_cast<qulonglong>(dirs.size()));
    for (const auto& w : pe_->warnings()) info += "\n⚠ " + QString::fromStdString(w);
    setPageInfo(info);

    for (size_t i = 0; i < dirs.size(); ++i) {
        const auto& d = dirs[i];
        const bool standard = pe::PeFile::isStandardDataDirectory(i);
        const uint64_t entryOff = pe_->dataDirectoriesOffset() + i * sizeof(pe::DataDirectory);
        QString fileOff = "-";
        std::optional<uint64_t> dataOff;
        if (d.VirtualAddress != 0) {
            // Security 디렉터리는 예외적으로 RVA가 아니라 파일 오프셋이다
            if (i == 4)  // IMAGE_DIRECTORY_ENTRY_SECURITY
                dataOff = d.VirtualAddress;
            else if (auto off = pe_->rvaToOffset(d.VirtualAddress))
                dataOff = *off;
            fileOff = dataOff ? hex(*dataOff, 8) : tr("(매핑 불가)");
        }
        // 더블클릭 → 실제 데이터 위치 (없으면 디렉터리 엔트리 자체)
        addRowText({hex(entryOff, 8), QString::number(i),
                    standard ? QString(pe::dataDirectoryName(i)) : tr("(비표준 확장)"), hex(d.VirtualAddress, 8),
                    hex(d.Size, 8), fileOff},
                   dataOff.value_or(entryOff), dataOff ? d.Size : sizeof(pe::DataDirectory));

        if (!standard) {  // 로더가 무시하는 확장 디렉터리는 색으로 구분
            const int row = table_->rowCount() - 1;
            for (int c = 0; c < table_->columnCount(); ++c)
                table_->item(row, c)->setForeground(QColor(0xC0, 0x60, 0x00));
        }
    }
}

void MainWindow::showSection(int index) {
    clearTable(kFieldHeaders);
    const auto& secs = pe_->sections();
    if (index < 0 || index >= static_cast<int>(secs.size())) return;
    const auto& s = secs[index];
    const uint64_t b = pe_->sectionTableOffset() + index * sizeof(pe::SectionHeader);

    addRowText({hex(b, 8), "Name", "8", QString::fromStdString(pe::sectionName(s)), {}}, b, 8);
    ADD_FIELD(b, s, VirtualSize);
    ADD_FIELD(b, s, VirtualAddress);
    ADD_FIELD(b, s, SizeOfRawData);
    ADD_FIELD(b, s, PointerToRawData);
    ADD_FIELD(b, s, PointerToRelocations);
    ADD_FIELD(b, s, PointerToLinenumbers);
    ADD_FIELD(b, s, NumberOfRelocations);
    ADD_FIELD(b, s, NumberOfLinenumbers);
    ADD_FIELD(b, s, Characteristics, QString::fromStdString(pe::sectionCharacteristicsToString(s.Characteristics)));

    if (s.SizeOfRawData > 0 && s.PointerToRawData < pe_->raw().size())
        setPageInfo(tr("섹션 데이터: File Offset %1 ~ %2  (트리의 SECTION %3 노드에서 hex 확인)")
                        .arg(hex(s.PointerToRawData, 8), hex(s.PointerToRawData + s.SizeOfRawData - 1, 8),
                             QString::fromStdString(pe::sectionName(s))));
}

// ---------------------------------------------------------------------------
// 파일 전체 hex 에서 헤더 구조를 색으로 구분
// ---------------------------------------------------------------------------

std::vector<HexRegion> MainWindow::headerRegions() const {
    const uint64_t nt = pe_->ntHeadersOffset();
    const uint64_t secTable = pe_->sectionTableOffset();
    const uint64_t dataDirs = pe_->dataDirectoriesOffset();
    const size_t numSecs = pe_->sections().size();

    struct H {
        uint64_t b, e;
        QColor c;
        QString label;
    };
    const std::vector<H> hdr = {
        {0, sizeof(pe::DosHeader), QColor(0xFF, 0xE0, 0xB2), "IMAGE_DOS_HEADER"},
        {pe_->dosStubOffset(), pe_->dosStubOffset() + pe_->dosStubSize(), QColor(0xE0, 0xE0, 0xE0), "DOS Stub"},
        {nt, nt + 4, QColor(0xFF, 0xCD, 0xD2), "NT Signature"},
        {pe_->fileHeaderOffset(), pe_->optionalHeaderOffset(), QColor(0xC5, 0xCA, 0xE9), "IMAGE_FILE_HEADER"},
        {pe_->optionalHeaderOffset(), dataDirs, QColor(0xB3, 0xE5, 0xFC), "IMAGE_OPTIONAL_HEADER"},
        {dataDirs, dataDirs + pe_->dataDirectories().size() * sizeof(pe::DataDirectory), QColor(0xB2, 0xDF, 0xDB),
         "Data Directories"},
        {secTable, secTable + numSecs * sizeof(pe::SectionHeader), QColor(0xDC, 0xED, 0xC8), "Section Table"},
    };

    std::vector<HexRegion> regions;
    for (const auto& h : hdr)
        if (h.e > h.b) regions.push_back({h.b, h.e, h.c, h.label});
    return regions;
}
