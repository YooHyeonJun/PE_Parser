// Base Relocation 화면 (트리 배치는 SectionPages.cpp 의 buildSectionNodes 가 담당)
#include "gui/GuiCommon.h"
#include "gui/MainWindow.h"

#include <QTableWidget>

using namespace gui;

namespace {

QString sectionOf(const pe::PeFile& pe, uint32_t rva) {
    if (auto sec = pe.sectionIndexForRva(rva)) return QString::fromStdString(pe::sectionName(pe.sections()[*sec]));
    return QStringLiteral("-");
}

// 재배치 대상 위치의 현재(디스크/이미지상) 값
QString targetValue(const pe::PeFile& pe, const pe::RelocEntry& e) {
    switch (e.type) {
        case pe::kRelocHighLow: {
            uint32_t v = 0;
            return pe.readRva(e.rva, v) ? hex(v, 8) : QObject::tr("(읽기 불가)");
        }
        case pe::kRelocDir64: {
            uint64_t v = 0;
            return pe.readRva(e.rva, v) ? hex(v, 16) : QObject::tr("(읽기 불가)");
        }
        case pe::kRelocHigh:
        case pe::kRelocLow:
        case pe::kRelocHighAdj: {
            uint16_t v = 0;
            return pe.readRva(e.rva, v) ? hex(v, 4) : QObject::tr("(읽기 불가)");
        }
        default: return {};
    }
}

}  // namespace

void MainWindow::showRelocBlocks() {
    clearTable({"File Offset", "Page RVA", "SizeOfBlock", "Entries", "Section"});
    const auto& blocks = pe_->relocations();

    size_t total = 0, padding = 0;
    for (const auto& b : blocks)
        for (const auto& e : b.entries) {
            ++total;
            padding += (e.type == pe::kRelocAbsolute && !e.isHighAdjParam);
        }

    table_->setUpdatesEnabled(false);
    for (const auto& b : blocks) {
        addRowText({offStr(b.headerOffset), hex(b.header.VirtualAddress, 8), hex(b.header.SizeOfBlock, 8),
                    QString::number(b.entries.size()), sectionOf(*pe_, b.header.VirtualAddress)},
                   isVirtualOffset(b.headerOffset) ? kNoJump : b.headerOffset, b.header.SizeOfBlock);
    }
    table_->setUpdatesEnabled(true);

    const auto& fh = pe_->fileHeader();
    QString note;
    if (fh.Characteristics & 0x0001) note = tr("  ※ RELOCS_STRIPPED 플래그가 켜져 있습니다.");
    setPageInfo(tr("Base Relocation 블록 %1개, 항목 %2개 (패딩 ABSOLUTE %3개 포함). "
                   "이미지가 ImageBase(%4)가 아닌 곳에 로드되면 각 위치에 (실제 주소 − ImageBase)를 더합니다.%5")
                    .arg(blocks.size())
                    .arg(static_cast<qulonglong>(total))
                    .arg(static_cast<qulonglong>(padding))
                    .arg(hex(pe_->imageBase(), pe_->is64() ? 16 : 8), note));
}

void MainWindow::showRelocBlock(int index) {
    const auto& blocks = pe_->relocations();
    if (index < 0 || index >= static_cast<int>(blocks.size())) return;
    const auto& b = blocks[index];
    const uint16_t machine = pe_->fileHeader().Machine;

    clearTable({"File Offset", "Raw", "Type", "Offset", "Target RVA", "Target Offset", "Current Value"});
    table_->setUpdatesEnabled(false);
    for (const auto& e : b.entries) {
        QString type, rva, tOff, value;
        if (e.isHighAdjParam) {
            type = tr("(HIGHADJ 파라미터)");
        } else if (e.type == pe::kRelocAbsolute) {
            type = tr("ABSOLUTE (패딩)");
        } else {
            type = QString::fromUtf8(pe::relocTypeToString(e.type, machine));
            rva = hex(e.rva, 8);
            tOff = offStr(pe_->fileOffsetOr(e.rva));
            value = targetValue(*pe_, e);
        }
        addRowText({offStr(e.entryOffset), hex(e.raw, 4), type, e.isHighAdjParam ? QString() : hex(e.offset, 3), rva,
                    tOff, value},
                   isVirtualOffset(e.entryOffset) ? kNoJump : e.entryOffset, 2);
    }
    table_->setUpdatesEnabled(true);

    setPageInfo(tr("Page %1 (%2)    블록 헤더 %3    SizeOfBlock %4    항목 %5개<br>"
                   "<small>WORD = Type(상위 4비트) | Offset(하위 12비트). Target RVA = Page + Offset. "
                   "Current Value = 재배치 전 값 (ImageBase 기준 주소).</small>")
                    .arg(hex(b.header.VirtualAddress, 8), sectionOf(*pe_, b.header.VirtualAddress),
                         offStr(b.headerOffset), hex(b.header.SizeOfBlock, 8))
                    .arg(b.entries.size()));
}
