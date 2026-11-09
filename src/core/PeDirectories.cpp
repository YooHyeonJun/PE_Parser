// 디렉터리: Import / Export 파싱 + 구조 위치(Region) 기록
//
// 모든 읽기는 RVA 기준(readRva, PeSections.cpp) — 구조가 파일에 없는 가상(0) 영역에 걸쳐 있어도 로더처럼 읽힌다.
// 여기서의 이상은 전부 경고로만 남기고, 헤더/섹션 정보는 그대로 보여준다.
#include "core/PeFile.h"

namespace pe {

namespace {
constexpr size_t kMaxNameLen = 65536;  // Import/Export 이름 최대 길이 (로더는 긴 이름도 허용 — corkami dllweirdexp)
}  // namespace

const DataDirectory* PeFile::directory(size_t index) const {
    // 로더와 동일하게 표준 16개 범위 안에서만 의미가 있다
    if (index >= dataDirs_.size() || index >= kNumDataDirectories) return nullptr;
    const auto& d = dataDirs_[index];
    // 로더는 Import/Export 를 VirtualAddress 만 보고 찾는다 (Import 는 0 Descriptor 로 끝을 판단, Size 무시).
    // → Size == 0 이어도 VA 가 있으면 유효한 디렉터리로 본다.
    return d.VirtualAddress == 0 ? nullptr : &d;
}

void PeFile::addRegion(RegionKind kind, uint64_t offset, uint64_t size, std::string label) {
    if (size == 0 || offset >= data_.size()) return;
    size = std::min<uint64_t>(size, data_.size() - offset);  // 파일 끝을 넘지 않게
    regions_.push_back({offset, size, kind, std::move(label)});
}

void PeFile::addRvaRegion(RegionKind kind, uint32_t rva, uint64_t size, std::string label) {
    if (auto off = rvaToOffset(rva)) addRegion(kind, *off, size, std::move(label));
}

// ---------------------------------------------------------------------------
// Import
//   ImportDescriptor[] ─┬─ Name ──────────────→ "KERNEL32.dll"
//                       ├─ OriginalFirstThunk → ILT[] ─→ (Ordinal) 또는 Hint/Name{ uint16 hint; char name[] }
//                       └─ FirstThunk ────────→ IAT[]  (디스크상으론 보통 ILT 와 같은 내용, 로드 후 함수 주소)
// ---------------------------------------------------------------------------

void PeFile::parseImports() {
    constexpr size_t kMaxModules = 4096;
    constexpr size_t kMaxFunctionsPerModule = 65536;

    const DataDirectory* dir = directory(kDirImport);
    if (!dir) return;

    const uint32_t descRva0 = dir->VirtualAddress;
    if (!spanAtRva(descRva0).mapped) return warn("Import Directory RVA가 이미지 범위를 벗어납니다.");

    const uint32_t thunkSize = is64_ ? 8 : 4;

    // 파일 전체 Import 항목 총량 상한: Thunk 배열을 서로 겹치게 만들어 (DLL 수 × 배열 길이) 만큼
    // 일을 시키는 파일(분석기 DoS, 예: corkami manyimportsW7)에서 멈추지 않도록 한다.
    constexpr size_t kMaxTotalFunctions = 1u << 18;  // 262,144
    size_t totalFunctions = 0;

    for (size_t m = 0;; ++m) {
        if (totalFunctions >= kMaxTotalFunctions)
            return warn("Import 함수 항목이 " + std::to_string(kMaxTotalFunctions) +
                        "개를 넘어 파싱을 중단했습니다 (Thunk 배열이 겹치는 비정상 구조일 수 있음). DLL " +
                        std::to_string(imports_.size()) + "개까지 표시합니다.");
        if (m >= kMaxModules) return warn("Import DLL이 너무 많아 " + std::to_string(kMaxModules) + "개에서 중단합니다.");

        const uint32_t descRva = descRva0 + static_cast<uint32_t>(m * sizeof(ImportDescriptor));
        ImportModule mod;
        mod.descriptorOffset = fileOffsetOr(descRva);
        if (!readRva(descRva, mod.descriptor))
            return warn("Import Descriptor 배열이 이미지 범위를 벗어납니다 (종료 항목 없음).");

        const auto& d = mod.descriptor;
        // 종료 조건: 로더와 동일 — Name 또는 FirstThunk 가 0 이면 끝 (나머지 필드는 쓰레기여도 무관)
        if (d.Name == 0 || d.FirstThunk == 0) {
            addRvaRegion(RegionKind::ImportDescriptor, descRva0, (m + 1) * sizeof(ImportDescriptor),
                         "Import Descriptors (" + std::to_string(m) + " + 종료 항목)");
            break;
        }

        // 문자열을 실제로 읽었을 때만 영역 기록 (실패 시 대체 문자열 길이로 잘못 칠하지 않도록)
        if (auto s = readStringAtRva(d.Name, kMaxNameLen)) {
            mod.dllName = *s;
            addRvaRegion(RegionKind::DllName, d.Name, s->size() + 1, "DLL Name: " + *s);
        } else {
            mod.dllName = "(이름 읽기 실패)";
        }

        // ILT 가 없으면(OriginalFirstThunk == 0, 일부 구형 링커) IAT 를 대신 읽는다
        const uint32_t lookupRva = d.OriginalFirstThunk ? d.OriginalFirstThunk : d.FirstThunk;

        for (size_t i = 0;; ++i) {
            if (i >= kMaxFunctionsPerModule) {
                warn(mod.dllName + ": 함수가 너무 많아 중단합니다.");
                break;
            }
            if (totalFunctions >= kMaxTotalFunctions) break;  // 바깥 루프에서 경고 후 중단
            ++totalFunctions;

            const uint32_t thunkRva = lookupRva + static_cast<uint32_t>(i * thunkSize);
            uint64_t thunk = 0;
            bool ok;
            if (is64_) {
                ok = readRva(thunkRva, thunk);
            } else {
                uint32_t t32 = 0;
                ok = readRva(thunkRva, t32);
                thunk = t32;
            }
            if (!ok) {
                warn(mod.dllName + ": Thunk 배열이 이미지 범위를 벗어납니다.");
                break;
            }
            if (thunk == 0) break;  // 배열 종료

            ImportFunction fn;
            fn.thunkOffset = fileOffsetOr(thunkRva);
            fn.thunkValue = thunk;
            fn.iatRva = d.FirstThunk + static_cast<uint32_t>(i * thunkSize);
            fn.byOrdinal = is64_ ? (thunk & kOrdinalFlag64) != 0 : (thunk & kOrdinalFlag32) != 0;

            if (fn.byOrdinal) {
                fn.ordinal = static_cast<uint16_t>(thunk & 0xFFFF);
            } else {
                // 하위 31비트 = IMAGE_IMPORT_BY_NAME 의 RVA
                const uint32_t hintNameRva = static_cast<uint32_t>(thunk & 0x7FFFFFFF);
                if (readRva(hintNameRva, fn.hint)) {
                    if (auto s = readStringAtRva(hintNameRva + 2, kMaxNameLen)) {
                        fn.name = *s;
                        addRvaRegion(RegionKind::ImportHintName, hintNameRva, 2 + s->size() + 1,
                                     "Hint/Name: " + *s + " (" + mod.dllName + ")");
                    } else {
                        fn.name = "(이름 읽기 실패)";
                    }
                } else {
                    fn.name = "(Hint/Name RVA가 이미지 범위 밖)";
                }
            }
            mod.functions.push_back(std::move(fn));
        }

        // Thunk 배열 위치 (종료용 0 항목 포함)
        const uint64_t arraySize = (mod.functions.size() + 1) * thunkSize;
        if (d.OriginalFirstThunk) addRvaRegion(RegionKind::ImportLookupTable, lookupRva, arraySize, "ILT: " + mod.dllName);
        addRvaRegion(RegionKind::ImportAddressTable, d.FirstThunk, arraySize, "IAT: " + mod.dllName);

        imports_.push_back(std::move(mod));
    }
}

// ---------------------------------------------------------------------------
// Export
//   AddressOfFunctions[i]     : Ordinal (Base + i) 함수의 RVA
//   AddressOfNames[j]         : j번째 이름 문자열 RVA
//   AddressOfNameOrdinals[j]  : j번째 이름이 가리키는 AddressOfFunctions 인덱스 i
//   함수 RVA 가 Export Directory 범위 안을 가리키면 → 코드가 아니라 Forwarder 문자열 ("DLL.Func")
// ---------------------------------------------------------------------------

void PeFile::parseExports() {
    constexpr uint32_t kMaxEntries = 65536;  // Ordinal 은 16비트

    const DataDirectory* dir = directory(kDirExport);
    if (!dir) return;

    ExportInfo info;
    if (!readRva(dir->VirtualAddress, info.directory)) return warn("Export Directory가 이미지 범위를 벗어납니다.");
    info.directoryOffset = fileOffsetOr(dir->VirtualAddress);
    addRvaRegion(RegionKind::ExportDirectory, dir->VirtualAddress, sizeof(ExportDirectory), "Export Directory");

    const auto& ed = info.directory;
    // Export 쪽 DLL 이름은 Export Names 영역에 포함 (DllName 종류는 Import 전용)
    if (auto s = readStringAtRva(ed.Name, kMaxNameLen)) {
        info.dllName = *s;
        addRvaRegion(RegionKind::ExportName, ed.Name, s->size() + 1, "Export DLL Name: " + *s);
    } else {
        info.dllName = "(이름 읽기 실패)";
    }

    uint32_t numFuncs = ed.NumberOfFunctions;
    uint32_t numNames = ed.NumberOfNames;
    if (numFuncs > kMaxEntries) {
        warn("Export NumberOfFunctions(" + std::to_string(numFuncs) + ")가 비정상적으로 큽니다. 65536개로 제한합니다.");
        numFuncs = kMaxEntries;
    }
    if (numNames > kMaxEntries) {
        warn("Export NumberOfNames(" + std::to_string(numNames) + ")가 비정상적으로 큽니다. 65536개로 제한합니다.");
        numNames = kMaxEntries;
    }

    // 1) 함수 주소 테이블 → 인덱스별 항목 생성
    std::vector<ExportFunction> all(numFuncs);
    for (uint32_t i = 0; i < numFuncs; ++i) {
        const uint32_t entryRva = ed.AddressOfFunctions + i * 4;
        all[i].ordinal = ed.Base + i;
        all[i].entryOffset = fileOffsetOr(entryRva);
        if (!readRva(entryRva, all[i].rva)) {
            warn("Export 함수 주소 테이블이 이미지 범위를 벗어납니다.");
            all.resize(i);
            numFuncs = i;
            break;
        }
    }
    if (numFuncs > 0)
        addRvaRegion(RegionKind::ExportAddressTable, ed.AddressOfFunctions, numFuncs * 4ull,
                     "Export Address Table (" + std::to_string(numFuncs) + ")");

    // 2) 이름 테이블 + 이름→인덱스 테이블 → 해당 인덱스에 이름 부여
    if (numNames > 0) {
        addRvaRegion(RegionKind::ExportNameTable, ed.AddressOfNames, numNames * 4ull,
                     "Export Name Pointer Table (" + std::to_string(numNames) + ")");
        addRvaRegion(RegionKind::ExportOrdinalTable, ed.AddressOfNameOrdinals, numNames * 2ull,
                     "Export Ordinal Table (" + std::to_string(numNames) + ")");
    }
    for (uint32_t j = 0; j < numNames; ++j) {
        uint32_t nameRva = 0;
        uint16_t index = 0;
        if (!readRva(ed.AddressOfNames + j * 4, nameRva) || !readRva(ed.AddressOfNameOrdinals + j * 2, index)) {
            warn("Export 이름 테이블이 이미지 범위를 벗어납니다.");
            break;
        }
        if (index >= numFuncs) {
            warn("Export 이름 #" + std::to_string(j) + "의 인덱스가 함수 테이블 범위를 벗어납니다.");
            continue;
        }
        std::string name = "(이름 읽기 실패)";
        if (auto s = readStringAtRva(nameRva, kMaxNameLen)) {
            name = *s;
            addRvaRegion(RegionKind::ExportName, nameRva, s->size() + 1, "Export Name: " + *s);
        }
        auto& fn = all[index];
        fn.name = fn.name.empty() ? name : fn.name + " / " + name;  // 같은 함수에 별칭이 여러 개인 경우
    }

    // 3) Forwarder 판별 + 빈 슬롯 제거
    const uint32_t dirBegin = dir->VirtualAddress;
    const uint32_t dirEnd = dir->VirtualAddress + dir->Size;
    for (auto& fn : all) {
        if (fn.rva == 0) continue;
        if (fn.rva >= dirBegin && fn.rva < dirEnd) {
            if (auto s = readStringAtRva(fn.rva, kMaxNameLen)) {
                fn.forwarder = *s;
                addRvaRegion(RegionKind::ExportForwarder, fn.rva, s->size() + 1, "Forwarder: " + *s);
            } else {
                fn.forwarder = "(읽기 실패)";
            }
        }
        info.functions.push_back(std::move(fn));
    }

    exports_ = std::move(info);
}

}  // namespace pe
