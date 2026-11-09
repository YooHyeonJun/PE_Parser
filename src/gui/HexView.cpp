#include "gui/HexView.h"

#include <QFontDatabase>
#include <QHeaderView>
#include <QItemSelection>

#include <algorithm>

namespace {
QString hex8(uint64_t v) {
    return QStringLiteral("0x%1").arg(v, 8, 16, QLatin1Char('0')).toUpper().replace("0X", "0x");
}
}  // namespace

// ---------------------------------------------------------------------------
// HexModel
// ---------------------------------------------------------------------------

void HexModel::setBytes(const uint8_t* data, size_t size, uint64_t baseOffset, std::optional<int64_t> rvaDelta,
                        std::vector<HexRegion> regions) {
    beginResetModel();
    data_ = data;
    size_ = data ? size : 0;
    base_ = baseOffset;
    rvaDelta_ = rvaDelta;
    regions_ = std::move(regions);
    std::sort(regions_.begin(), regions_.end(), [](const HexRegion& a, const HexRegion& b) { return a.begin < b.begin; });
    endResetModel();
}

QModelIndex HexModel::indexForOffset(uint64_t off) const {
    if (off < base_ || off - base_ >= size_) return {};
    const uint64_t rel = off - base_;
    return index(static_cast<int>(rel / kBytesPerRow), kColFirstByte + static_cast<int>(rel % kBytesPerRow));
}

int HexModel::rowCount(const QModelIndex& parent) const {
    return parent.isValid() ? 0 : static_cast<int>((size_ + kBytesPerRow - 1) / kBytesPerRow);
}

int HexModel::columnCount(const QModelIndex& parent) const {
    return parent.isValid() ? 0 : kColAscii + 1;
}

const HexRegion* HexModel::regionAt(uint64_t off) const {
    // begin <= off 인 마지막 구간을 이진 탐색 → 그 구간이 off 를 포함하는지 확인
    auto it = std::upper_bound(regions_.begin(), regions_.end(), off,
                               [](uint64_t v, const HexRegion& r) { return v < r.begin; });
    if (it == regions_.begin()) return nullptr;
    --it;
    return off < it->end ? &*it : nullptr;
}

QVariant HexModel::data(const QModelIndex& index, int role) const {
    if (!index.isValid() || !data_) return {};
    const uint64_t rowStart = static_cast<uint64_t>(index.row()) * kBytesPerRow;
    const int col = index.column();

    // 바이트 셀
    if (col >= kColFirstByte && col < kColAscii) {
        const uint64_t rel = rowStart + (col - kColFirstByte);
        if (rel >= size_) return {};
        const uint64_t off = base_ + rel;
        const uint8_t b = data_[rel];

        switch (role) {
            case Qt::DisplayRole:
                return QStringLiteral("%1").arg(b, 2, 16, QLatin1Char('0')).toUpper();
            case Qt::TextAlignmentRole:
                return Qt::AlignCenter;
            case Qt::BackgroundRole:
                if (auto* r = regionAt(off)) return r->color;
                return {};
            case Qt::ForegroundRole:  // 색 배경 위에서는 다크 테마에서도 읽히게 검정 글자
                if (regionAt(off)) return QColor(Qt::black);
                return {};
            case Qt::ToolTipRole: {
                QString tip = QStringLiteral("File Offset %1").arg(hex8(off));
                if (rvaDelta_) tip += QStringLiteral("   RVA %1").arg(hex8(static_cast<uint64_t>(off + *rvaDelta_)));
                if (auto* r = regionAt(off))
                    tip += QStringLiteral("\n%1\n(%2 ~ %3, %4 bytes)")
                               .arg(r->label, hex8(r->begin), hex8(r->end - 1))
                               .arg(r->end - r->begin);
                return tip;
            }
            default:
                return {};
        }
    }

    if (role != Qt::DisplayRole) return {};

    switch (col) {
        case kColOffset:
            return hex8(base_ + rowStart);
        case kColRva:
            return rvaDelta_ ? hex8(static_cast<uint64_t>(base_ + rowStart + *rvaDelta_)) : QString();
        case kColAscii: {
            QString s;
            const uint64_t end = std::min<uint64_t>(rowStart + kBytesPerRow, size_);
            for (uint64_t i = rowStart; i < end; ++i) {
                const uint8_t b = data_[i];
                s += (b >= 0x20 && b < 0x7F) ? QChar(b) : QChar('.');
            }
            return s;
        }
        default:
            return {};
    }
}

QVariant HexModel::headerData(int section, Qt::Orientation orientation, int role) const {
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole) return {};
    if (section == kColOffset) return QStringLiteral("File Offset");
    if (section == kColRva) return QStringLiteral("RVA");
    if (section == kColAscii) return QStringLiteral("ASCII");
    return QStringLiteral("%1").arg(section - kColFirstByte, 2, 16, QLatin1Char('0')).toUpper();
}

// ---------------------------------------------------------------------------
// HexView
// ---------------------------------------------------------------------------

HexView::HexView(QWidget* parent) : QTableView(parent), model_(new HexModel(this)) {
    setModel(model_);
    setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    setEditTriggers(QAbstractItemView::NoEditTriggers);
    setSelectionMode(QAbstractItemView::ExtendedSelection);
    setWordWrap(false);
    setShowGrid(false);
    verticalHeader()->setVisible(false);

    // 고정 행 높이/열 폭 → 대용량에서도 빠름
    const QFontMetrics fm(font());
    verticalHeader()->setSectionResizeMode(QHeaderView::Fixed);
    verticalHeader()->setDefaultSectionSize(fm.height() + 4);
    horizontalHeader()->setSectionResizeMode(QHeaderView::Fixed);
    horizontalHeader()->setStretchLastSection(true);
    setColumnWidth(HexModel::kColOffset, fm.horizontalAdvance("0x00000000") + 16);
    setColumnWidth(HexModel::kColRva, fm.horizontalAdvance("0x00000000") + 16);
    for (int c = HexModel::kColFirstByte; c < HexModel::kColAscii; ++c) setColumnWidth(c, fm.horizontalAdvance("00") + 10);
}

void HexView::selectRange(uint64_t off, uint64_t length) {
    const QModelIndex first = model_->indexForOffset(off);
    if (!first.isValid()) return;

    const uint64_t base = model_->baseOffset();
    const uint64_t rel = off - base;
    // 선택은 최대 64KB 까지만 (너무 큰 구조 선택 시 UI 지연 방지)
    const uint64_t len = std::clamp<uint64_t>(length, 1, std::min<uint64_t>(model_->byteCount() - rel, 64 * 1024));
    const uint64_t end = rel + len;

    QItemSelection sel;
    constexpr uint64_t W = HexModel::kBytesPerRow;
    for (uint64_t row = rel / W; row * W < end; ++row) {
        const int c0 = static_cast<int>(std::max(rel, row * W) - row * W);
        const int c1 = static_cast<int>(std::min(end, row * W + W) - 1 - row * W);
        sel.select(model_->index(static_cast<int>(row), HexModel::kColFirstByte + c0),
                   model_->index(static_cast<int>(row), HexModel::kColFirstByte + c1));
    }
    selectionModel()->select(sel, QItemSelectionModel::ClearAndSelect);
    selectionModel()->setCurrentIndex(first, QItemSelectionModel::NoUpdate);
    scrollTo(first, QAbstractItemView::PositionAtCenter);
    setFocus();
}
