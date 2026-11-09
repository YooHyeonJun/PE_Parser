#pragma once

#include <QAbstractTableModel>
#include <QColor>
#include <QTableView>

#include <cstdint>
#include <optional>
#include <vector>

// Hex 뷰에서 색으로 표시할 구간
struct HexRegion {
    uint64_t begin = 0;  // 파일 오프셋 [begin, end)
    uint64_t end = 0;
    QColor color;
    QString label;  // 툴팁에 표시
};

// 바이트 배열을 [File Offset | RVA | 00..0F | ASCII] 표로 보여주는 모델.
// 보이는 행만 data()가 호출되므로 수 MB 섹션도 즉시 표시된다.
class HexModel : public QAbstractTableModel {
    Q_OBJECT

public:
    static constexpr int kBytesPerRow = 16;
    static constexpr int kColOffset = 0;
    static constexpr int kColRva = 1;
    static constexpr int kColFirstByte = 2;
    static constexpr int kColAscii = kColFirstByte + kBytesPerRow;

    using QAbstractTableModel::QAbstractTableModel;

    // data 는 호출자가 수명을 보장해야 한다 (PeFile::raw() 내부를 가리킴).
    // rvaDelta: RVA = fileOffset + rvaDelta (없으면 RVA 열을 비움)
    void setBytes(const uint8_t* data, size_t size, uint64_t baseOffset, std::optional<int64_t> rvaDelta,
                  std::vector<HexRegion> regions);

    uint64_t baseOffset() const { return base_; }
    size_t byteCount() const { return size_; }
    QModelIndex indexForOffset(uint64_t fileOffset) const;  // 범위 밖이면 invalid

    int rowCount(const QModelIndex& parent = {}) const override;
    int columnCount(const QModelIndex& parent = {}) const override;
    QVariant data(const QModelIndex& index, int role) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override;

private:
    const HexRegion* regionAt(uint64_t fileOffset) const;

    const uint8_t* data_ = nullptr;
    size_t size_ = 0;
    uint64_t base_ = 0;
    std::optional<int64_t> rvaDelta_;
    std::vector<HexRegion> regions_;  // begin 기준 정렬
};

class HexView : public QTableView {
    Q_OBJECT

public:
    explicit HexView(QWidget* parent = nullptr);

    HexModel* hexModel() const { return model_; }

    // [fileOffset, fileOffset+length) 바이트를 선택하고 화면 가운데로 스크롤
    void selectRange(uint64_t fileOffset, uint64_t length);

private:
    HexModel* model_;
};
