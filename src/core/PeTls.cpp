// TLS: Data Directory #9 (IMAGE_TLS_DIRECTORY) + 콜백 배열 + 초기값 템플릿
//
//   IMAGE_TLS_DIRECTORY ─┬─ Start/EndAddressOfRawData ─→ [초기값 템플릿]  (+ SizeOfZeroFill 만큼 0)
//                        ├─ AddressOfIndex ────────────→ DWORD (로더가 TLS 슬롯 번호를 기록)
//                        └─ AddressOfCallBacks ────────→ [콜백 VA, 콜백 VA, ..., NULL]
//
// * 주소 필드는 전부 VA (ImageBase 포함) → vaToRva() 로 변환해서 읽는다.
// * 콜백은 로더가 EntryPoint 보다 먼저 호출 → 안티디버깅 / 패커가 즐겨 쓰는 위치.
// * 여기서의 이상은 전부 경고로만 남긴다.
#include "core/PeFile.h"

#include <cstdio>

namespace pe {

namespace {
constexpr size_t kMaxTlsCallbacks = 4096;

std::string hexVa(uint64_t v) {
    char b[24];
    std::snprintf(b, sizeof b, "0x%llX", static_cast<unsigned long long>(v));
    return b;
}
}  // namespace

void PeFile::parseTls() {
    const DataDirectory* dir = directory(kDirTls);
    if (!dir) return;

    TlsInfo info;
    const uint32_t dirRva = dir->VirtualAddress;
    bool ok;
    if (is64_) {
        ok = readRva(dirRva, info.dir64);
        const auto& d = info.dir64;
        info.startAddressOfRawData = d.StartAddressOfRawData;
        info.endAddressOfRawData = d.EndAddressOfRawData;
        info.addressOfIndex = d.AddressOfIndex;
        info.addressOfCallBacks = d.AddressOfCallBacks;
        info.sizeOfZeroFill = d.SizeOfZeroFill;
        info.characteristics = d.Characteristics;
    } else {
        ok = readRva(dirRva, info.dir32);
        const auto& d = info.dir32;
        info.startAddressOfRawData = d.StartAddressOfRawData;
        info.endAddressOfRawData = d.EndAddressOfRawData;
        info.addressOfIndex = d.AddressOfIndex;
        info.addressOfCallBacks = d.AddressOfCallBacks;
        info.sizeOfZeroFill = d.SizeOfZeroFill;
        info.characteristics = d.Characteristics;
    }
    if (!ok) return warn("TLS Directory가 이미지 범위를 벗어납니다.");

    const uint32_t dirSize = is64_ ? sizeof(TlsDirectory64) : sizeof(TlsDirectory32);
    info.directoryOffset = fileOffsetOr(dirRva);
    addRvaRegion(RegionKind::TlsDirectory, dirRva, dirSize, "TLS Directory");

    // 1) 초기값 템플릿 [Start, End)
    if (info.startAddressOfRawData || info.endAddressOfRawData) {
        if (info.endAddressOfRawData < info.startAddressOfRawData) {
            warn("TLS EndAddressOfRawData가 StartAddressOfRawData보다 작습니다.");
        } else if (auto rva = vaToRva(info.startAddressOfRawData)) {
            const uint64_t size = info.endAddressOfRawData - info.startAddressOfRawData;
            if (size > sizeOfImage())
                warn("TLS 템플릿 크기(" + hexVa(size) + ")가 SizeOfImage보다 큽니다.");
            else
                addRvaRegion(RegionKind::TlsRawData, *rva, size, "TLS Raw Data (" + std::to_string(size) + " bytes)");
        } else {
            warn("TLS StartAddressOfRawData(" + hexVa(info.startAddressOfRawData) + ")가 이미지 범위 밖입니다.");
        }
    }

    // 2) AddressOfIndex — 로더가 여기에 값을 쓴다
    if (info.addressOfIndex && !vaToRva(info.addressOfIndex))
        warn("TLS AddressOfIndex(" + hexVa(info.addressOfIndex) + ")가 이미지 범위 밖입니다.");

    // 3) 콜백 배열
    if (info.addressOfCallBacks) {
        const auto arrRva = vaToRva(info.addressOfCallBacks);
        if (!arrRva) {
            warn("TLS AddressOfCallBacks(" + hexVa(info.addressOfCallBacks) + ")가 이미지 범위 밖입니다.");
        } else {
            info.callbackArrayOffset = fileOffsetOr(*arrRva);
            const uint32_t ptrSize = is64_ ? 8 : 4;
            bool terminated = false;
            size_t outside = 0;
            for (size_t i = 0; i < kMaxTlsCallbacks; ++i) {
                const uint32_t slotRva = *arrRva + static_cast<uint32_t>(i * ptrSize);
                uint64_t va = 0;
                if (is64_) {
                    ok = readRva(slotRva, va);
                } else {
                    uint32_t v32 = 0;
                    ok = readRva(slotRva, v32);
                    va = v32;
                }
                if (!ok) {
                    warn("TLS 콜백 배열이 이미지 범위를 벗어납니다 (종료 NULL 없음).");
                    break;
                }
                if (va == 0) {
                    terminated = true;
                    break;
                }

                TlsCallback cb;
                cb.va = va;
                cb.entryOffset = fileOffsetOr(slotRva);
                cb.rva = vaToRva(va);
                if (cb.rva)
                    cb.codeOffset = fileOffsetOr(*cb.rva);
                else
                    ++outside;
                info.callbacks.push_back(cb);
            }
            if (outside)
                warn("TLS 콜백 " + std::to_string(info.callbacks.size()) + "개 중 " + std::to_string(outside) +
                     "개가 이미지 밖을 가리킵니다 (로드 시 IAT 등으로 덮어써지거나, 앞선 콜백이 런타임에 배열을 바꾸는 경우).");
            if (!terminated && info.callbacks.size() >= kMaxTlsCallbacks)
                warn("TLS 콜백이 " + std::to_string(kMaxTlsCallbacks) + "개를 넘어 중단했습니다.");

            const uint64_t arrBytes = (info.callbacks.size() + (terminated ? 1 : 0)) * ptrSize;
            addRvaRegion(RegionKind::TlsCallbacks, *arrRva, arrBytes,
                         "TLS Callbacks (" + std::to_string(info.callbacks.size()) + ")");

            // 콜백 배열이 IAT 와 겹치면 로드 시 import 주소로 덮어써진다 (디스크 값 ≠ 실제 호출 대상)
            const uint64_t arrBegin = *arrRva, arrEnd = arrBegin + std::max<uint64_t>(arrBytes, ptrSize);
            for (const auto& m : imports_) {
                const uint64_t iatBegin = m.descriptor.FirstThunk;
                const uint64_t iatEnd = iatBegin + (m.functions.size() + 1) * ptrSize;
                if (arrBegin < iatEnd && iatBegin < arrEnd) {
                    warn("TLS 콜백 배열이 " + m.dllName +
                         " 의 IAT와 겹칩니다 — 로드 시 import 함수 주소로 덮어써져 디스크상 값과 실제 호출 대상이 다릅니다.");
                    break;
                }
            }
        }
    }

    tls_ = std::move(info);
}

}  // namespace pe
