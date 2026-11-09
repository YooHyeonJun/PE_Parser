// 섹션 화면: 트리의 SECTION 노드 + 섹션 안 구조 노드 배치, 섹션 원본 hex, 미파싱 디렉터리 hex
#include "gui/GuiCommon.h"
#include "gui/HexView.h"
#include "gui/MainWindow.h"

#include <QTreeWidget>

#include <algorithm>
#include <map>

using namespace gui;

// ---------------------------------------------------------------------------
// 트리: SECTION .xxx 노드와, 그 섹션 안에 실제로 위치한 구조 노드
//   각 구조는 파일상 위치(섹션)에 붙이고, 같은 섹션 안에서는 오프셋 순으로 정렬한다.
//   섹션 밖(헤더 영역 / Overlay)에 있는 구조는 루트 아래에 붙인다.
// ---------------------------------------------------------------------------

void MainWindow::buildSectionNodes(QTreeWidgetItem* root) {
    const auto& sections = pe_->sections();
    sectionDataItems_.assign(sections.size(), nullptr);
    for (int i = 0; i < static_cast<int>(sections.size()); ++i)
        sectionDataItems_[i] =
            makeTreeItem(root, "SECTION " + QString::fromStdString(pe::sectionName(sections[i])), Page::SectionData, i);

    struct Node {
        uint64_t offset;
        QString label;
        Page page;
        int index;
        bool importDlls = false;  // IMPORT Directory Table 아래에 DLL 별 노드
    };
    std::vector<Node> nodes;

    // 같은 종류 영역들 중 가장 앞 오프셋
    auto firstOffset = [&](std::initializer_list<pe::RegionKind> kinds) -> std::optional<uint64_t> {
        std::optional<uint64_t> best;
        for (const auto& r : pe_->regions())
            if (std::find(kinds.begin(), kinds.end(), r.kind) != kinds.end() && (!best || r.offset < *best))
                best = r.offset;
        return best;
    };
    auto addNode = [&](std::optional<uint64_t> off, const QString& label, Page page, int index = -1, bool dlls = false) {
        if (off) nodes.push_back({*off, label, page, index, dlls});
    };

    // 파싱한 디렉터리 (Import / Export)
    using K = pe::RegionKind;
    if (!pe_->imports().empty()) {
        addNode(firstOffset({K::ImportDescriptor}), "IMPORT Directory Table", Page::Imports, -1, true);
        addNode(firstOffset({K::ImportAddressTable}), "IMPORT Address Table", Page::ImportAddressTable);
        addNode(firstOffset({K::ImportLookupTable}), "IMPORT Name Table", Page::ImportNameTable);
        addNode(firstOffset({K::ImportHintName, K::DllName}), "IMPORT Hints/Names & DLL Names", Page::ImportHintNames);
    }
    if (pe_->exports()) {
        addNode(firstOffset({K::ExportDirectory}), "IMAGE_EXPORT_DIRECTORY", Page::ExportDirectory);
        addNode(firstOffset({K::ExportAddressTable}), "EXPORT Address Table", Page::ExportFunctions);
        addNode(firstOffset({K::ExportNameTable}), "EXPORT Name Pointer Table", Page::ExportNameTable);
        addNode(firstOffset({K::ExportOrdinalTable}), "EXPORT Ordinal Table", Page::ExportOrdinalTable);
        addNode(firstOffset({K::ExportName, K::ExportForwarder}), "EXPORT Names", Page::ExportNames);
    }

    // 아직 파싱하지 않은 디렉터리는 원본 바이트 노드로 (Import/Export/IAT 는 위에서 처리)
    static const char* kDirNodeNames[pe::kNumDataDirectories] = {
        nullptr, nullptr, "IMAGE_RESOURCE_DIRECTORY", "IMAGE_RUNTIME_FUNCTION_ENTRY (Exception)", "CERTIFICATE Table",
        "IMAGE_BASE_RELOCATION", "IMAGE_DEBUG_DIRECTORY", "Architecture", "Global Ptr", "IMAGE_TLS_DIRECTORY",
        "IMAGE_LOAD_CONFIG_DIRECTORY", "IMAGE_BOUND_IMPORT_DESCRIPTOR", nullptr, "DELAY IMPORT Descriptors",
        "IMAGE_COR20_HEADER (CLR)", nullptr};
    for (size_t i = 0; i < pe::kNumDataDirectories; ++i) {
        const char* name = kDirNodeNames[i];
        if (i == pe::kDirImport && pe_->imports().empty()) name = "IMPORT Directory Table";
        if (i == pe::kDirExport && !pe_->exports()) name = "IMAGE_EXPORT_DIRECTORY";
        if (i == 12 && pe_->imports().empty()) name = "IMPORT Address Table";
        if (!name) continue;
        addNode(directoryFileOffset(i), QString(name) + "  (raw)", Page::DirectoryData, static_cast<int>(i));
    }

    std::stable_sort(nodes.begin(), nodes.end(), [](const Node& a, const Node& b) { return a.offset < b.offset; });
    for (const auto& n : nodes) {
        const auto sec = pe_->sectionIndexForOffset(n.offset);
        QTreeWidgetItem* parent = sec ? sectionDataItems_[*sec] : root;
        auto* item = makeTreeItem(parent, n.label, n.page, n.index);
        if (n.importDlls) {
            const auto& imports = pe_->imports();
            for (int i = 0; i < static_cast<int>(imports.size()); ++i)
                makeTreeItem(item,
                             QString("%1 (%2)").arg(QString::fromStdString(imports[i].dllName)).arg(imports[i].functions.size()),
                             Page::ImportModule, i);
        }
    }
}

// ---------------------------------------------------------------------------
// 위치 계산 헬퍼
// ---------------------------------------------------------------------------

QStringList MainWindow::directoriesInSection(size_t sectionIndex) const {
    QStringList names;
    const auto& dirs = pe_->dataDirectories();
    for (size_t i = 0; i < dirs.size() && i < pe::kNumDataDirectories; ++i) {
        const auto& d = dirs[i];
        if (d.VirtualAddress == 0 || d.Size == 0) continue;
        // Security(#4)는 RVA 가 아니라 파일 오프셋
        const auto idx = (i == 4) ? pe_->sectionIndexForOffset(d.VirtualAddress) : pe_->sectionIndexForRva(d.VirtualAddress);
        if (idx && *idx == sectionIndex) names << pe::dataDirectoryName(i);
    }
    return names;
}

std::optional<uint64_t> MainWindow::directoryFileOffset(size_t i) const {
    const auto& dirs = pe_->dataDirectories();
    if (i >= dirs.size() || dirs[i].VirtualAddress == 0 || dirs[i].Size == 0) return std::nullopt;
    if (i == 4) return dirs[i].VirtualAddress;  // Security: RVA 가 아니라 파일 오프셋
    if (auto off = pe_->rvaToOffset(dirs[i].VirtualAddress)) return *off;
    return std::nullopt;
}

std::vector<HexRegion> MainWindow::parsedRegionsIn(uint64_t begin, uint64_t end) const {
    std::vector<HexRegion> out;
    for (const auto& r : pe_->regions()) {
        if (r.offset < end && r.offset + r.size > begin)
            out.push_back({r.offset, r.offset + r.size, regionColor(r.kind), QString::fromStdString(r.label)});
    }
    return out;
}

// ---------------------------------------------------------------------------
// 페이지
// ---------------------------------------------------------------------------

void MainWindow::showSectionData(int index) {
    const auto& secs = pe_->sections();
    if (index < 0 || index >= static_cast<int>(secs.size())) return;
    const auto& s = secs[index];
    const QString name = QString::fromStdString(pe::sectionName(s)).toHtmlEscaped();

    if (s.SizeOfRawData == 0 || s.PointerToRawData >= pe_->raw().size()) {
        showHex(0, 0, std::nullopt, {},
                tr("<b>%1</b> &nbsp; 디스크에 저장된 데이터가 없습니다 (SizeOfRawData = %2). "
                   "메모리에만 할당되는 섹션입니다 (VirtualSize %3).")
                    .arg(name, hex(s.SizeOfRawData, 8), hex(s.VirtualSize, 8)));
        return;
    }

    const uint64_t begin = s.PointerToRawData;
    const uint64_t end = std::min<uint64_t>(begin + s.SizeOfRawData, pe_->raw().size());
    auto regions = parsedRegionsIn(begin, end);

    // 범례: 이 섹션에 실제로 있는 구조 종류 + 개수
    std::map<int, int> kindCount;
    for (const auto& r : pe_->regions())
        if (r.offset < end && r.offset + r.size > begin) ++kindCount[static_cast<int>(r.kind)];
    std::vector<std::pair<QString, QColor>> legend;
    for (const auto& [k, n] : kindCount) {
        const auto kind = static_cast<pe::RegionKind>(k);
        legend.push_back({QString("%1 (%2)").arg(pe::regionKindName(kind)).arg(n), regionColor(kind)});
    }

    QString info = tr("<b>%1</b> &nbsp; File Offset %2 ~ %3 (%4 bytes) &nbsp; RVA %5 ~ %6")
                       .arg(name, hex(begin, 8), hex(end - 1, 8))
                       .arg(end - begin)
                       .arg(hex(s.VirtualAddress, 8), hex(s.VirtualAddress + (end - begin) - 1, 8));
    const QStringList dirs = directoriesInSection(index);
    if (!dirs.isEmpty()) info += tr("<br>포함된 디렉터리: %1").arg(dirs.join(", "));
    if (!legend.empty()) info += "<br>" + legendHtml(legend);
    info += tr("<br><small>바이트에 마우스를 올리면 구조 이름이 보입니다. 다른 화면의 행을 더블클릭하면 이곳으로 이동합니다.</small>");

    const int64_t rvaDelta = static_cast<int64_t>(s.VirtualAddress) - static_cast<int64_t>(s.PointerToRawData);
    showHex(begin, static_cast<size_t>(end - begin), rvaDelta, std::move(regions), info);
}

void MainWindow::showDirectoryData(int i) {
    const auto& dirs = pe_->dataDirectories();
    const auto off = directoryFileOffset(static_cast<size_t>(i));
    if (!off || i < 0 || i >= static_cast<int>(dirs.size())) return;
    const auto& d = dirs[i];

    std::optional<int64_t> rvaDelta;
    if (i != 4) rvaDelta = static_cast<int64_t>(d.VirtualAddress) - static_cast<int64_t>(*off);

    std::vector<HexRegion> regions = parsedRegionsIn(*off, *off + d.Size);
    const QString info = tr("<b>%1</b> &nbsp; File Offset %2 &nbsp; RVA %3 &nbsp; Size %4<br>"
                            "<small>아직 구조를 파싱하지 않은 디렉터리입니다 — 원본 바이트만 표시합니다.</small>")
                             .arg(pe::dataDirectoryName(i), hex(*off, 8), hex(d.VirtualAddress, 8), hex(d.Size, 8));
    showHex(*off, d.Size, rvaDelta, std::move(regions), info);
}
