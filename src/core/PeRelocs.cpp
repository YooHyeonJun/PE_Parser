// Base Relocation: Data Directory #5
//
//   [블록 헤더 {VirtualAddress, SizeOfBlock}] [WORD 항목 × (SizeOfBlock-8)/2] [다음 블록 헤더] ...
//   항목 WORD = Type(상위 4비트) | Offset(하위 12비트) → 고칠 위치 RVA = VirtualAddress + Offset
//
// 이미지가 선호 ImageBase 가 아닌 곳에 로드되면(ASLR 등) 로더가 각 위치의 값에 (실제 Base - ImageBase)를 더한다.
//
// 로더 관점 규칙
//  * Import 와 달리 디렉터리 Size 를 따른다 — Size 만큼 블록을 순서대로 처리
//    (단, 각 블록의 항목 수는 SizeOfBlock 으로 계산 — 마지막 블록이 Size 를 넘어도 끝까지 읽는다)
//  * SizeOfBlock < 8 이면 더 진행할 수 없으므로 중단
//  * ABSOLUTE(0) 항목은 4바이트 정렬용 패딩
//  * HIGHADJ(4) 는 다음 WORD 를 파라미터로 함께 소비
// 여기서의 이상은 전부 경고로만 남긴다.
#include "core/PeFile.h"

#include <cstdio>

namespace pe {

namespace {
constexpr size_t kMaxRelocBlocks = 65536;
// 전체 항목 상한: 실제 항목은 파일 바이트에 있어야 하므로 (파일 크기 / 2)를 넘을 수 없다.
// 가상(0) 영역을 가리키는 거대한 SizeOfBlock 같은 기형 파일만 막으면 된다.
// (고정 2M 상한은 실제 .NET 네이티브 이미지(.ni.dll, 약 257만 항목)에서 걸렸음)
constexpr size_t kMinRelocEntryCap = 1u << 21;

std::string hex8(uint32_t v) {
    char b[16];
    std::snprintf(b, sizeof b, "0x%08X", v);
    return b;
}

// 이 Type 이 고치는 바이트 수 (0 = 고치지 않음 / 알 수 없음)
uint32_t relocWidth(uint8_t type) {
    switch (type) {
        case kRelocHigh:
        case kRelocLow:
        case kRelocHighAdj: return 2;
        case kRelocHighLow: return 4;
        case kRelocDir64: return 8;
        default: return 0;
    }
}
}  // namespace

void PeFile::parseRelocations() {
    const DataDirectory* dir = directory(kDirBaseReloc);
    if (!dir) return;
    if (dir->Size == 0) return warn("Base Relocation 디렉터리 VirtualAddress는 있지만 Size가 0입니다 — 로더는 무시합니다.");

    const uint64_t dirBegin = dir->VirtualAddress;
    const uint64_t dirEnd = dirBegin + dir->Size;
    uint64_t cur = dirBegin;
    size_t totalEntries = 0;
    const size_t kMaxRelocEntries = std::max<size_t>(kMinRelocEntryCap, data_.size() / 2);
    size_t outsideImage = 0, unknownType = 0;

    while (cur + sizeof(BaseRelocationBlock) <= dirEnd) {
        if (relocs_.size() >= kMaxRelocBlocks) {
            warn("Relocation 블록이 " + std::to_string(kMaxRelocBlocks) + "개를 넘어 중단했습니다.");
            break;
        }
        if (cur > 0xFFFFFFFFull) break;
        const uint32_t blockRva = static_cast<uint32_t>(cur);

        RelocBlock blk;
        if (!readRva(blockRva, blk.header)) {
            warn("Relocation 블록 " + hex8(blockRva) + "이 이미지 범위를 벗어납니다.");
            break;
        }
        blk.headerOffset = fileOffsetOr(blockRva);
        const auto& h = blk.header;

        if (h.SizeOfBlock < sizeof(BaseRelocationBlock)) {
            // SizeOfBlock 0 은 흔한 "끝 표시" 관행 — 경고하지 않음
            if (h.SizeOfBlock != 0 || h.VirtualAddress != 0)
                warn("Relocation 블록 " + hex8(blockRva) + "의 SizeOfBlock(" + std::to_string(h.SizeOfBlock) +
                     ")이 8보다 작아 중단합니다.");
            break;
        }

        // 로더는 블록 항목 수를 SizeOfBlock 으로만 계산한다 (디렉터리 Size 로 자르지 않음) → 그대로 따른다
        if (cur + h.SizeOfBlock > dirEnd)
            warn("Relocation 블록 " + hex8(blockRva) + "이 디렉터리 Size를 넘어갑니다 — 로더처럼 SizeOfBlock 기준으로 모두 읽습니다.");
        const size_t count = (h.SizeOfBlock - sizeof(BaseRelocationBlock)) / 2;

        addRvaRegion(RegionKind::RelocBlockHeader, blockRva, sizeof(BaseRelocationBlock),
                     "Reloc Block: page " + hex8(h.VirtualAddress));

        bool nextIsParam = false;
        for (size_t i = 0; i < count; ++i) {
            if (totalEntries >= kMaxRelocEntries) break;
            const uint32_t entRva = blockRva + static_cast<uint32_t>(sizeof(BaseRelocationBlock) + i * 2);
            uint16_t w = 0;
            if (!readRva(entRva, w)) {
                warn("Relocation 항목 배열이 이미지 범위를 벗어납니다.");
                break;
            }
            RelocEntry e;
            e.raw = w;
            e.type = static_cast<uint8_t>(w >> 12);
            e.offset = static_cast<uint16_t>(w & 0x0FFF);
            e.rva = h.VirtualAddress + e.offset;
            e.entryOffset = fileOffsetOr(entRva);
            e.isHighAdjParam = nextIsParam;
            nextIsParam = !e.isHighAdjParam && e.type == kRelocHighAdj;

            if (!e.isHighAdjParam && e.type != kRelocAbsolute) {
                const uint32_t width = relocWidth(e.type);
                // 5/7/9 는 아키텍처 전용 Type (ARM/MIPS 명령어 패치) — 크기 검사 생략
                if (width == 0 && e.type != 5 && e.type != 7 && e.type != 9) ++unknownType;
                // 고칠 위치 전체가 이미지 안인지 (로더는 범위 밖이면 실패)
                if (width) {
                    const uint64_t endRva = static_cast<uint64_t>(e.rva) + width;
                    if (endRva > sizeOfImage() || !spanAtRva(e.rva).mapped) ++outsideImage;
                }
            }
            blk.entries.push_back(e);
            ++totalEntries;
        }

        if (count > 0)
            addRvaRegion(RegionKind::RelocEntries, blockRva + sizeof(BaseRelocationBlock), count * 2ull,
                         "Reloc Entries: page " + hex8(h.VirtualAddress) + " (" + std::to_string(count) + ")");

        relocs_.push_back(std::move(blk));
        if (totalEntries >= kMaxRelocEntries) {
            warn("Relocation 항목이 " + std::to_string(kMaxRelocEntries) + "개를 넘어 중단했습니다.");
            break;
        }
        cur += h.SizeOfBlock;  // 다음 블록 (잘린 경우 루프 조건에서 끝남)
    }

    if (outsideImage)
        warn("Relocation 항목 " + std::to_string(outsideImage) +
             "개가 이미지 밖(SizeOfImage 초과 / 매핑 안 됨)을 가리킵니다 — 재배치가 필요하면 로드에 실패합니다.");
    if (unknownType)
        warn("정의되지 않은 Relocation Type 항목이 " + std::to_string(unknownType) +
             "개 있습니다 — 재배치가 필요하면 로더가 거부할 수 있습니다 (Windows 버전마다 다름).");
}

}  // namespace pe
