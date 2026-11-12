// 섹션: Section Table 파싱 + 주소 매핑 (RVA ↔ 파일 오프셋, 메모리 이미지 관점 읽기)
//
// 메모리 이미지 관점 (로더가 매핑한 모습 기준)
//   파일에 있는 바이트 → 파일 내용
//   매핑은 되지만 파일에 없는 영역 (섹션 뒷부분, 헤더 페이지 나머지, 파일 끝 너머) → 0
//   매핑되지 않은 RVA → 실패
#include "core/PeFile.h"

namespace pe {

namespace {
uint64_t alignUp(uint64_t v, uint64_t a) { return a ? (v + a - 1) / a * a : v; }
}  // namespace

// ---------------------------------------------------------------------------
// Section Table
//   위치 = Optional Header 시작 + SizeOfOptionalHeader (헤더와 겹칠 수 있음)
//   최대 65535개 (Vista/7+). 파일 끝을 넘는 부분은 읽지 않고 경고.
// ---------------------------------------------------------------------------

void PeFile::parseSectionTable() {
    const uint64_t secOff = sectionTableOffset();
    const uint16_t numSecs = fileHeader_.NumberOfSections;
    sections_.reserve(numSecs);
    for (uint32_t i = 0; i < numSecs; ++i) {
        const uint64_t off = secOff + i * sizeof(SectionHeader);
        if (off >= data_.size()) {
            warn("섹션 테이블이 파일 끝을 넘어갑니다: " + std::to_string(numSecs) + "개 중 " + std::to_string(i) +
                 "개만 읽었습니다.");
            break;
        }
        SectionHeader sh{};
        readPadded(off, sh);  // 마지막 항목이 일부 잘렸으면 0으로 채움
        sections_.push_back(sh);
    }
}

std::optional<size_t> PeFile::sectionIndexForRva(uint32_t rva) const {
    for (size_t i = 0; i < sections_.size(); ++i) {
        const auto& s = sections_[i];
        const uint32_t span = std::max(s.VirtualSize, s.SizeOfRawData);
        if (rva >= s.VirtualAddress && rva - s.VirtualAddress < span) return i;
    }
    return std::nullopt;
}

std::optional<size_t> PeFile::sectionIndexForOffset(uint64_t offset) const {
    for (size_t i = 0; i < sections_.size(); ++i) {
        const auto& s = sections_[i];
        if (s.SizeOfRawData && offset >= s.PointerToRawData && offset - s.PointerToRawData < s.SizeOfRawData) return i;
    }
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// 주소 매핑
// ---------------------------------------------------------------------------

PeFile::RvaSpan PeFile::spanAtRva(uint32_t rva) const {
    const uint64_t fileSize = data_.size();

    // Low-alignment: 파일 전체가 그대로 매핑
    if (isLowAlignment()) {
        if (rva < fileSize) return {true, rva, fileSize - rva};
        if (rva < sizeOfImage()) return {true, std::nullopt, sizeOfImage() - rva};
        return {};
    }

    // 헤더
    const uint64_t hdrSize = sizeOfHeaders();
    if (rva < hdrSize) {
        if (rva < fileSize) return {true, rva, std::min(hdrSize, fileSize) - rva};
        return {true, std::nullopt, hdrSize - rva};
    }

    // 섹션
    if (auto idx = sectionIndexForRva(rva)) {
        const auto& s = sections_[*idx];
        const uint64_t delta = rva - s.VirtualAddress;
        const uint64_t span = std::max(s.VirtualSize, s.SizeOfRawData);
        const uint64_t rawLen = s.PointerToRawData < fileSize
                                    ? std::min<uint64_t>(s.SizeOfRawData, fileSize - s.PointerToRawData)
                                    : 0;
        if (delta < rawLen) return {true, s.PointerToRawData + delta, rawLen - delta};
        return {true, std::nullopt, span - delta};
    }

    // 헤더 페이지의 나머지 (SizeOfHeaders ~ SectionAlignment 경계) — 0으로 매핑됨
    uint64_t hdrPageEnd = alignUp(hdrSize, sectionAlignment());
    for (const auto& s : sections_)
        if (s.VirtualAddress > rva) hdrPageEnd = std::min<uint64_t>(hdrPageEnd, s.VirtualAddress);
    if (rva < hdrPageEnd) return {true, std::nullopt, hdrPageEnd - rva};

    return {};
}

std::optional<uint32_t> PeFile::rvaToOffset(uint32_t rva) const {
    // 파일에 실제 바이트가 있는 경우만 (가상/미매핑 영역은 nullopt)
    const RvaSpan sp = spanAtRva(rva);
    if (!sp.fileOffset) return std::nullopt;
    return static_cast<uint32_t>(*sp.fileOffset);
}

uint64_t PeFile::fileOffsetOr(uint32_t rva) const {
    const RvaSpan sp = spanAtRva(rva);
    return sp.fileOffset ? *sp.fileOffset : kNoFileOffset;
}

// ---------------------------------------------------------------------------
// 메모리 이미지 관점 읽기
// ---------------------------------------------------------------------------

bool PeFile::readRva(uint32_t rva, void* dst, size_t size) const {
    auto* out = static_cast<uint8_t*>(dst);
    uint64_t cur = rva;
    while (size > 0) {
        if (cur > 0xFFFFFFFFull) return false;
        const RvaSpan sp = spanAtRva(static_cast<uint32_t>(cur));
        if (!sp.mapped || sp.length == 0) return false;
        const size_t n = static_cast<size_t>(std::min<uint64_t>(sp.length, size));
        if (sp.fileOffset)
            std::memcpy(out, data_.data() + *sp.fileOffset, n);
        else
            std::memset(out, 0, n);  // 가상 영역 = 0
        out += n;
        cur += n;
        size -= n;
    }
    return true;
}

std::optional<std::string> PeFile::readStringAtRva(uint32_t rva, size_t maxLen) const {
    std::string s;
    uint64_t cur = rva;
    while (s.size() < maxLen) {
        if (cur > 0xFFFFFFFFull) return std::nullopt;
        const RvaSpan sp = spanAtRva(static_cast<uint32_t>(cur));
        if (!sp.mapped || sp.length == 0) return std::nullopt;
        if (!sp.fileOffset) return s;  // 가상 영역은 0 → 여기서 문자열 끝

        const char* p = reinterpret_cast<const char*>(data_.data() + *sp.fileOffset);
        const size_t n = static_cast<size_t>(std::min<uint64_t>(sp.length, maxLen - s.size()));
        const size_t len = strnlen(p, n);
        s.append(p, len);
        if (len < n) return s;  // NUL 발견
        cur += n;
    }
    return std::nullopt;  // maxLen 안에 NUL 없음
}

std::optional<uint32_t> PeFile::vaToRva(uint64_t va) const {
    const uint64_t base = imageBase();
    if (va < base || va - base > 0xFFFFFFFFull) return std::nullopt;
    const auto rva = static_cast<uint32_t>(va - base);
    if (!spanAtRva(rva).mapped) return std::nullopt;
    return rva;
}

}  // namespace pe
