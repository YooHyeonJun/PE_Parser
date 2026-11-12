// TLS 화면 (트리 배치는 SectionPages.cpp 의 buildSectionNodes 가 담당)
#include "gui/GuiCommon.h"
#include "gui/MainWindow.h"

#include <QTableWidget>

using namespace gui;

namespace {

// VA 하나를 "RVA 0x.. (.text) / File 0x.." 로 설명
QString describeVa(const pe::PeFile& pe, uint64_t va) {
    if (va == 0) return QStringLiteral("-");
    const auto rva = pe.vaToRva(va);
    if (!rva) return QObject::tr("이미지 밖");
    QString s = QStringLiteral("RVA %1").arg(hex(*rva, 8));
    if (auto sec = pe.sectionIndexForRva(*rva))
        s += QStringLiteral(" (%1)").arg(QString::fromStdString(pe::sectionName(pe.sections()[*sec])));
    s += QStringLiteral(", File %1").arg(offStr(pe.fileOffsetOr(*rva)));
    return s;
}

}  // namespace

void MainWindow::showTlsDirectory() {
    clearTable(kFieldHeaders);
    const auto& tls = pe_->tls();
    if (!tls) return;
    const uint64_t b = tls->directoryOffset;

    const uint64_t rawSize =
        tls->endAddressOfRawData >= tls->startAddressOfRawData ? tls->endAddressOfRawData - tls->startAddressOfRawData : 0;
    const uint32_t align = (tls->characteristics >> 20) & 0xF;  // IMAGE_SCN_ALIGN_* 와 같은 인코딩
    const QString alignDesc = align ? tr("정렬 %1 바이트").arg(1u << (align - 1)) : tr("정렬 지정 없음");

    auto fill = [&](const auto& d) {
        ADD_FIELD(b, d, StartAddressOfRawData, tr("템플릿 시작 VA — ") + describeVa(*pe_, d.StartAddressOfRawData));
        ADD_FIELD(b, d, EndAddressOfRawData, tr("템플릿 끝 VA (크기 %1)").arg(rawSize));
        ADD_FIELD(b, d, AddressOfIndex, tr("TLS 인덱스 변수 VA — ") + describeVa(*pe_, d.AddressOfIndex));
        ADD_FIELD(b, d, AddressOfCallBacks, tr("콜백 배열 VA — ") + describeVa(*pe_, d.AddressOfCallBacks));
        ADD_FIELD(b, d, SizeOfZeroFill, tr("템플릿 뒤 0 채움 크기"));
        ADD_FIELD(b, d, Characteristics, alignDesc);
    };
    if (pe_->is64())
        fill(tls->dir64);
    else
        fill(tls->dir32);

    setPageInfo(tr("IMAGE_TLS_DIRECTORY%1 — 주소 필드는 RVA가 아니라 VA(ImageBase %2 포함)입니다. 콜백 %3개.")
                    .arg(pe_->is64() ? "64" : "32", hex(pe_->imageBase(), pe_->is64() ? 16 : 8))
                    .arg(tls->callbacks.size()));
}

void MainWindow::showTlsCallbacks() {
    clearTable({"File Offset", "#", "Callback VA", "RVA", "Section", "Code Offset"});
    const auto& tls = pe_->tls();
    if (!tls) return;
    const int w = pe_->is64() ? 16 : 8;
    const uint64_t ptrSize = pe_->is64() ? 8 : 4;

    table_->setUpdatesEnabled(false);
    for (size_t i = 0; i < tls->callbacks.size(); ++i) {
        const auto& cb = tls->callbacks[i];
        QString section = "-";
        if (cb.rva)
            if (auto sec = pe_->sectionIndexForRva(*cb.rva))
                section = QString::fromStdString(pe::sectionName(pe_->sections()[*sec]));
        addRowText({offStr(cb.entryOffset), QString::number(i), hex(cb.va, w), cb.rva ? hex(*cb.rva, 8) : tr("이미지 밖"),
                    section, offStr(cb.codeOffset)},
                   isVirtualOffset(cb.entryOffset) ? kNoJump : cb.entryOffset, ptrSize);
    }
    // 종료 NULL 항목
    if (!isVirtualOffset(tls->callbackArrayOffset)) {
        const uint64_t endOff = tls->callbackArrayOffset + tls->callbacks.size() * ptrSize;
        if (endOff < pe_->raw().size())
            addRowText({hex(endOff, 8), "-", hex(0, w), tr("End of CallBacks"), {}, {}}, endOff, ptrSize);
    }
    table_->setUpdatesEnabled(true);

    setPageInfo(tr("TLS 콜백 %1개 — 로더가 EntryPoint(%2)보다 먼저 호출합니다 (프로세스/스레드 시작·종료 시). "
                   "File Offset = 배열 슬롯 위치, Code Offset = 콜백 코드 위치.")
                    .arg(tls->callbacks.size())
                    .arg(hex(pe_->entryPoint(), 8)));
}
