#pragma once
// GUI 페이지 파일들(MainWindow / HeaderPages / SectionPages / DirectoryPages)이 공유하는 내부 헬퍼

#include "core/PeFile.h"
#include "core/PeFormat.h"

#include <QColor>
#include <QString>
#include <QStringList>

#include <cstdint>
#include <type_traits>
#include <utility>
#include <vector>

namespace gui {

// 트리/테이블 아이템에 저장하는 데이터 역할
constexpr int kRolePage = Qt::UserRole;             // 트리: 어떤 페이지인지
constexpr int kRoleIndex = Qt::UserRole + 1;        // 트리: 섹션/DLL/디렉터리 인덱스
constexpr int kRoleJumpOffset = Qt::UserRole + 10;  // 테이블 첫 열: 더블클릭 시 이동할 파일 오프셋
constexpr int kRoleJumpSize = Qt::UserRole + 11;

inline QString hex(uint64_t v, int width) {
    return QStringLiteral("0x%1").arg(v, width, 16, QLatin1Char('0')).toUpper().replace("0X", "0x");
}

// 파일 오프셋 표시: 파일에 없는(메모리에서만 0으로 채워지는) 위치면 "(virtual)"
// kNoFileOffset + 필드 오프셋 처럼 더해진 값도 가상으로 취급
inline bool isVirtualOffset(uint64_t off) { return off >= pe::kNoFileOffset - 0xFFFF; }
inline QString offStr(uint64_t off) { return isVirtualOffset(off) ? QStringLiteral("(virtual)") : hex(off, 8); }

// Hex 뷰 하이라이트 색 (밝은 파스텔 + 검정 글자)
inline QColor regionColor(pe::RegionKind k) {
    using K = pe::RegionKind;
    switch (k) {
        case K::ImportDescriptor: return QColor(0xFF, 0xD5, 0x9E);
        case K::ImportLookupTable: return QColor(0xC8, 0xE6, 0xC9);
        case K::ImportAddressTable: return QColor(0xBB, 0xDE, 0xFB);
        case K::ImportHintName: return QColor(0xF0, 0xF4, 0xC3);
        case K::DllName: return QColor(0xE1, 0xBE, 0xE7);
        case K::ExportDirectory: return QColor(0xFF, 0xCD, 0xD2);
        case K::ExportAddressTable: return QColor(0xB2, 0xEB, 0xF2);
        case K::ExportNameTable: return QColor(0xD7, 0xCC, 0xC8);
        case K::ExportOrdinalTable: return QColor(0xCF, 0xD8, 0xDC);
        case K::ExportName: return QColor(0xFF, 0xF9, 0xC4);
        case K::ExportForwarder: return QColor(0xF8, 0xBB, 0xD0);
    }
    return QColor(Qt::lightGray);
}

// 범례: [색] 이름
inline QString legendHtml(const std::vector<std::pair<QString, QColor>>& items) {
    QString html;
    for (const auto& [label, color] : items)
        html += QStringLiteral("<span style='background-color:%1; color:#000;'>&nbsp;%2&nbsp;</span>&nbsp; ")
                    .arg(color.name(), label.toHtmlEscaped());
    return html;
}

// 테이블 헤더. 모든 테이블의 첫 열은 "그 행의 데이터가 파일 안에 있는 위치"
inline const QStringList kFieldHeaders = {"File Offset", "Field", "Size", "Value", "Description"};  // 구조체 필드
inline const QStringList kStructHeaders = {"File Offset", "Data", "Description", "Value"};         // PEView 스타일

// PEView 스타일 테이블 한 행 (정렬 후 출력용)
struct StructRow {
    uint64_t offset;
    uint64_t size;
    QString data, desc, value;
};

}  // namespace gui

// 구조체 멤버 하나를 (이름, 파일오프셋, 크기, 값) 으로 테이블에 추가 — MainWindow 멤버 함수 안에서 사용
#define ADD_FIELD(base, s, member, ...)                                                              \
    addRow(QStringLiteral(#member), (base) + offsetof(std::remove_cvref_t<decltype(s)>, member),    \
           sizeof((s).member), static_cast<uint64_t>((s).member), ##__VA_ARGS__)
