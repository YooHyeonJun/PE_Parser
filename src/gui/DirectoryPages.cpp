// Import / Export 화면 (트리 배치는 SectionPages.cpp 의 buildSectionNodes 가 담당)
#include "gui/GuiCommon.h"
#include "gui/MainWindow.h"

#include <QDateTime>
#include <QTableWidget>
#include <QTimeZone>

#include <algorithm>

using namespace gui;

// ---------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------

void MainWindow::showImports() {
    clearTable({"File Offset", "DLL", "OriginalFirstThunk", "TimeDateStamp", "ForwarderChain", "Name", "FirstThunk",
                "Functions"});
    const auto& imports = pe_->imports();

    size_t total = 0;
    for (const auto& m : imports) total += m.functions.size();
    setPageInfo(tr("DLL %1개, 함수 %2개").arg(imports.size()).arg(static_cast<qulonglong>(total)));

    for (const auto& m : imports) {
        const auto& d = m.descriptor;
        addRowText({offStr(m.descriptorOffset), QString::fromStdString(m.dllName), hex(d.OriginalFirstThunk, 8),
                    hex(d.TimeDateStamp, 8), hex(d.ForwarderChain, 8), hex(d.Name, 8), hex(d.FirstThunk, 8),
                    QString::number(m.functions.size())},
                   m.descriptorOffset, sizeof(pe::ImportDescriptor));
    }
}

void MainWindow::showImportModule(int index) {
    const auto& imports = pe_->imports();
    if (index < 0 || index >= static_cast<int>(imports.size())) return;
    const auto& m = imports[index];
    const int thunkWidth = pe_->is64() ? 16 : 8;

    // File Offset = ILT 엔트리 위치 (ILT 가 없는 파일이면 IAT 엔트리 위치)
    clearTable({"File Offset", "IAT RVA", "Thunk Value", "Hint", "Name / Ordinal"});
    setPageInfo(tr("%1    Descriptor Offset: %2    ILT: %3    IAT: %4    함수 %5개")
                    .arg(QString::fromStdString(m.dllName), offStr(m.descriptorOffset),
                         hex(m.descriptor.OriginalFirstThunk, 8), hex(m.descriptor.FirstThunk, 8))
                    .arg(m.functions.size()));

    table_->setUpdatesEnabled(false);
    for (const auto& f : m.functions) {
        addRowText({offStr(f.thunkOffset), hex(f.iatRva, 8), hex(f.thunkValue, thunkWidth),
                    f.byOrdinal ? QString("-") : hex(f.hint, 4),
                    f.byOrdinal ? tr("Ordinal %1 (0x%2)").arg(f.ordinal).arg(f.ordinal, 4, 16, QLatin1Char('0'))
                                : QString::fromStdString(f.name)},
                   f.thunkOffset, pe_->is64() ? 8 : 4);
    }
    table_->setUpdatesEnabled(true);
}

void MainWindow::showImportThunks(bool iat) {
    clearTable(kStructHeaders);
    const bool is64 = pe_->is64();
    const size_t ts = is64 ? 8 : 4;
    const int w = is64 ? 16 : 8;
    // RVA 기준으로 읽는다 — 배열이 파일에 없는 가상(0) 영역에 걸쳐 있어도 로더가 보는 값(0)으로 표시
    auto readThunk = [&](uint32_t rva) -> uint64_t {
        if (is64) {
            uint64_t v = 0;
            pe_->readRva(rva, v);
            return v;
        }
        uint32_t v = 0;
        pe_->readRva(rva, v);
        return v;
    };
    auto addThunkRow = [&](uint32_t rva, const QStringList& rest) {
        const uint64_t off = pe_->fileOffsetOr(rva);
        addRowText(QStringList{offStr(off)} + rest, isVirtualOffset(off) ? kNoJump : off, ts);
    };

    size_t dlls = 0, entries = 0;
    table_->setUpdatesEnabled(false);
    for (const auto& m : pe_->imports()) {
        const uint32_t arrRva = iat ? m.descriptor.FirstThunk : m.descriptor.OriginalFirstThunk;
        if (!arrRva || !pe_->spanAtRva(arrRva).mapped) continue;
        ++dlls;
        for (size_t i = 0; i < m.functions.size(); ++i) {
            const auto& f = m.functions[i];
            const uint32_t rva = arrRva + static_cast<uint32_t>(i * ts);
            const uint64_t v = readThunk(rva);
            QString desc, val;
            if (iat && v != f.thunkValue) {  // 바인딩된 IAT: 디스크에 이미 주소가 들어 있음
                desc = tr("Bound Address");
            } else {
                desc = f.byOrdinal ? tr("Ordinal") : tr("Hint/Name RVA");
            }
            val = f.byOrdinal ? tr("Ordinal %1 (0x%2)").arg(f.ordinal).arg(f.ordinal, 4, 16, QLatin1Char('0'))
                              : QString("%1  %2").arg(hex(f.hint, 4), QString::fromStdString(f.name));
            addThunkRow(rva, {hex(v, w), desc, val});
        }
        const uint32_t endRva = arrRva + static_cast<uint32_t>(m.functions.size() * ts);
        addThunkRow(endRva, {hex(readThunk(endRva), w), tr("End of Imports"), QString::fromStdString(m.dllName)});
        entries += m.functions.size();
    }
    table_->setUpdatesEnabled(true);

    setPageInfo(iat ? tr("IMPORT Address Table (IAT) — DLL %1개, 항목 %2개. 디스크상 값은 ILT와 같고, "
                         "로드 시 로더가 실제 함수 주소로 덮어씁니다.")
                          .arg(dlls).arg(static_cast<qulonglong>(entries))
                    : tr("IMPORT Name Table (ILT, OriginalFirstThunk) — DLL %1개, 항목 %2개. "
                         "최상위 비트가 1이면 Ordinal, 아니면 Hint/Name RVA.")
                          .arg(dlls).arg(static_cast<qulonglong>(entries)));
}

void MainWindow::showImportHintNames() {
    clearTable(kStructHeaders);
    std::vector<StructRow> rows;
    for (const auto& m : pe_->imports()) {
        if (auto o = pe_->rvaToOffset(m.descriptor.Name))
            rows.push_back({*o, m.dllName.size() + 1, {}, tr("DLL Name"), QString::fromStdString(m.dllName)});
        for (const auto& f : m.functions) {
            if (f.byOrdinal) continue;
            if (auto o = pe_->rvaToOffset(static_cast<uint32_t>(f.thunkValue & 0x7FFFFFFF)))
                rows.push_back({*o, 2 + f.name.size() + 1, hex(f.hint, 4), tr("Hint/Name"), QString::fromStdString(f.name)});
        }
    }
    std::sort(rows.begin(), rows.end(), [](const StructRow& a, const StructRow& b) { return a.offset < b.offset; });

    table_->setUpdatesEnabled(false);
    for (const auto& r : rows) addRowText({hex(r.offset, 8), r.data, r.desc, r.value}, r.offset, r.size);
    table_->setUpdatesEnabled(true);
    setPageInfo(tr("IMPORT Hints/Names & DLL Names — %1개 (파일 오프셋 순). Hint/Name = { WORD Hint; CHAR Name[]; }")
                    .arg(static_cast<qulonglong>(rows.size())));
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

void MainWindow::showExportDirectory() {
    clearTable(kFieldHeaders);
    const auto& exp = pe_->exports();
    if (!exp) return;
    const auto& e = exp->directory;
    const uint64_t b = exp->directoryOffset;

    ADD_FIELD(b, e, Characteristics);
    ADD_FIELD(b, e, TimeDateStamp,
              QDateTime::fromSecsSinceEpoch(e.TimeDateStamp, QTimeZone::UTC).toString("yyyy-MM-dd hh:mm:ss UTC"));
    ADD_FIELD(b, e, MajorVersion);
    ADD_FIELD(b, e, MinorVersion);
    ADD_FIELD(b, e, Name, QString::fromStdString(exp->dllName));
    ADD_FIELD(b, e, Base, tr("시작 Ordinal"));
    ADD_FIELD(b, e, NumberOfFunctions);
    ADD_FIELD(b, e, NumberOfNames);
    ADD_FIELD(b, e, AddressOfFunctions, tr("RVA"));
    ADD_FIELD(b, e, AddressOfNames, tr("RVA"));
    ADD_FIELD(b, e, AddressOfNameOrdinals, tr("RVA"));
}

void MainWindow::showExportFunctions() {
    // File Offset = EAT(AddressOfFunctions) 엔트리 위치, Func Offset = 함수 코드의 파일 위치
    clearTable({"File Offset", "Ordinal", "RVA", "Func Offset", "Name", "Forwarder"});
    const auto& exp = pe_->exports();
    if (!exp) return;

    size_t named = 0, forwarded = 0;
    for (const auto& f : exp->functions) {
        named += !f.name.empty();
        forwarded += !f.forwarder.empty();
    }
    setPageInfo(tr("%1    함수 %2개 (이름 있음 %3, Ordinal 전용 %4, Forwarder %5)")
                    .arg(QString::fromStdString(exp->dllName))
                    .arg(exp->functions.size())
                    .arg(static_cast<qulonglong>(named))
                    .arg(static_cast<qulonglong>(exp->functions.size() - named))
                    .arg(static_cast<qulonglong>(forwarded)));

    table_->setUpdatesEnabled(false);
    for (const auto& f : exp->functions) {
        QString fileOff = "-";
        if (f.forwarder.empty()) {
            if (auto off = pe_->rvaToOffset(f.rva)) fileOff = hex(*off, 8);
        }
        addRowText({offStr(f.entryOffset), QString::number(f.ordinal), hex(f.rva, 8), fileOff,
                    f.name.empty() ? tr("(Ordinal 전용)") : QString::fromStdString(f.name),
                    QString::fromStdString(f.forwarder)},
                   f.entryOffset, 4);
    }
    table_->setUpdatesEnabled(true);
}

void MainWindow::showExportNameTable() {
    clearTable(kStructHeaders);
    const auto& exp = pe_->exports();
    if (!exp) return;
    const auto& ed = exp->directory;
    const auto namesOff = pe_->rvaToOffset(ed.AddressOfNames);
    if (!namesOff) return;

    table_->setUpdatesEnabled(false);
    const uint32_t n = std::min<uint32_t>(ed.NumberOfNames, 65536);
    for (uint32_t j = 0; j < n; ++j) {
        const uint64_t off = *namesOff + j * 4ull;
        uint32_t rva = 0;
        if (!pe_->read(off, rva)) break;
        addRowText({hex(off, 8), hex(rva, 8), tr("Function Name RVA"),
                    QString("%1  %2").arg(j, 4).arg(QString::fromStdString(pe_->readStringAtRva(rva).value_or("?")))},
                   off, 4);
    }
    table_->setUpdatesEnabled(true);
    setPageInfo(tr("EXPORT Name Pointer Table (AddressOfNames) — %1개, 이름 알파벳순 정렬 (로더가 이진 탐색)").arg(n));
}

void MainWindow::showExportOrdinalTable() {
    clearTable(kStructHeaders);
    const auto& exp = pe_->exports();
    if (!exp) return;
    const auto& ed = exp->directory;
    const auto ordsOff = pe_->rvaToOffset(ed.AddressOfNameOrdinals);
    const auto namesOff = pe_->rvaToOffset(ed.AddressOfNames);
    if (!ordsOff) return;

    table_->setUpdatesEnabled(false);
    const uint32_t n = std::min<uint32_t>(ed.NumberOfNames, 65536);
    for (uint32_t j = 0; j < n; ++j) {
        const uint64_t off = *ordsOff + j * 2ull;
        uint16_t index = 0;
        if (!pe_->read(off, index)) break;
        uint32_t nameRva = 0;
        const std::string name =
            (namesOff && pe_->read(*namesOff + j * 4ull, nameRva)) ? pe_->readStringAtRva(nameRva).value_or("?") : "?";
        addRowText({hex(off, 8), hex(index, 4), tr("Function Ordinal (index)"),
                    tr("Ordinal %1  %2").arg(ed.Base + index).arg(QString::fromStdString(name))},
                   off, 2);
    }
    table_->setUpdatesEnabled(true);
    setPageInfo(tr("EXPORT Ordinal Table (AddressOfNameOrdinals) — %1개. 값 = AddressOfFunctions 인덱스, "
                   "실제 Ordinal = Base(%2) + 인덱스")
                    .arg(n).arg(ed.Base));
}

void MainWindow::showExportNames() {
    clearTable(kStructHeaders);
    const auto& exp = pe_->exports();
    if (!exp) return;
    const auto& ed = exp->directory;

    std::vector<StructRow> rows;
    if (auto o = pe_->rvaToOffset(ed.Name))
        rows.push_back({*o, exp->dllName.size() + 1, {}, tr("DLL Name"), QString::fromStdString(exp->dllName)});

    if (const auto namesOff = pe_->rvaToOffset(ed.AddressOfNames)) {
        const uint32_t n = std::min<uint32_t>(ed.NumberOfNames, 65536);
        for (uint32_t j = 0; j < n; ++j) {
            uint32_t rva = 0;
            if (!pe_->read(*namesOff + j * 4ull, rva)) break;
            const auto o = pe_->rvaToOffset(rva);
            const auto s = pe_->readStringAtRva(rva);
            if (o && s) rows.push_back({*o, s->size() + 1, {}, tr("Function Name"), QString::fromStdString(*s)});
        }
    }
    for (const auto& f : exp->functions) {
        if (f.forwarder.empty()) continue;
        if (auto o = pe_->rvaToOffset(f.rva))
            rows.push_back({*o, f.forwarder.size() + 1, {}, tr("Forwarder"), QString::fromStdString(f.forwarder)});
    }
    std::sort(rows.begin(), rows.end(), [](const StructRow& a, const StructRow& b) { return a.offset < b.offset; });

    table_->setUpdatesEnabled(false);
    for (const auto& r : rows) addRowText({hex(r.offset, 8), r.data, r.desc, r.value}, r.offset, r.size);
    table_->setUpdatesEnabled(true);
    setPageInfo(tr("EXPORT Names — DLL 이름, 함수 이름, Forwarder 문자열 %1개 (파일 오프셋 순)")
                    .arg(static_cast<qulonglong>(rows.size())));
}
