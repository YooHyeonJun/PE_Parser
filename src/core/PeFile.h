#pragma once

#include "core/PeTypes.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace pe {

// 구조가 파일에 존재하지 않고 메모리(가상 영역, 0으로 채워짐)에만 있을 때의 오프셋 값
constexpr uint64_t kNoFileOffset = ~0ull;

// --- Import 파싱 결과 ---
struct ImportFunction {
    bool byOrdinal = false;
    uint16_t ordinal = 0;      // byOrdinal 일 때
    uint16_t hint = 0;         // 이름 import 일 때: Export Name Table 인덱스 힌트
    std::string name;          // 이름 import 일 때
    uint64_t thunkOffset = 0;  // 이 항목을 읽은 ILT(없으면 IAT) 엔트리의 파일 오프셋
    uint32_t iatRva = 0;       // 이 함수의 IAT 슬롯 RVA (로드 후 실제 주소가 기록되는 곳)
    uint64_t thunkValue = 0;   // ILT 항목 원본 값
};

struct ImportModule {
    ImportDescriptor descriptor{};
    uint64_t descriptorOffset = 0;  // 파일 오프셋
    std::string dllName;
    std::vector<ImportFunction> functions;
};

// --- Export 파싱 결과 ---
struct ExportFunction {
    uint32_t ordinal = 0;      // Base + 인덱스
    uint64_t entryOffset = 0;  // AddressOfFunctions(EAT) 엔트리의 파일 오프셋
    uint32_t rva = 0;
    std::string name;          // 이름 없이 Ordinal 로만 export 되면 ""
    std::string forwarder;     // "NTDLL.RtlAllocateHeap" 처럼 다른 DLL로 전달되면 그 문자열
};

struct ExportInfo {
    ExportDirectory directory{};
    uint64_t directoryOffset = 0;  // 파일 오프셋
    std::string dllName;
    std::vector<ExportFunction> functions;  // RVA 가 0 인 빈 슬롯은 제외
};

// --- Base Relocation 파싱 결과 ---
struct RelocEntry {
    uint16_t raw = 0;              // 원본 WORD
    uint8_t type = 0;              // 상위 4비트
    uint16_t offset = 0;           // 하위 12비트
    uint32_t rva = 0;              // 고칠 위치 = 블록 VirtualAddress + offset
    uint64_t entryOffset = 0;      // 이 WORD 의 파일 오프셋
    bool isHighAdjParam = false;   // HIGHADJ 바로 뒤 — 재배치 항목이 아니라 앞 항목의 파라미터
};

struct RelocBlock {
    BaseRelocationBlock header{};
    uint64_t headerOffset = 0;     // 파일 오프셋
    std::vector<RelocEntry> entries;
};

// --- 파일 안의 구조 위치 (Hex 뷰 하이라이트용) ---
enum class RegionKind {
    ImportDescriptor,    // Import Descriptor 배열
    ImportLookupTable,   // ILT (OriginalFirstThunk)
    ImportAddressTable,  // IAT (FirstThunk)
    ImportHintName,      // IMAGE_IMPORT_BY_NAME { hint; name }
    DllName,             // Import 대상 DLL 이름 문자열
    ExportDirectory,
    ExportAddressTable,  // AddressOfFunctions
    ExportNameTable,     // AddressOfNames
    ExportOrdinalTable,  // AddressOfNameOrdinals
    ExportName,          // Export 함수 이름 문자열
    ExportForwarder,     // Forwarder 문자열
    RelocBlockHeader,    // IMAGE_BASE_RELOCATION 블록 헤더 (8바이트)
    RelocEntries,        // 블록의 WORD 항목 배열
};

struct Region {
    uint64_t offset = 0;  // 파일 오프셋
    uint64_t size = 0;
    RegionKind kind{};
    std::string label;    // 예: "IAT: KERNEL32.dll", "Hint/Name: HeapAlloc"
};

// PE 파일 하나를 메모리에 올려 Windows 로더와 같은 관점으로 파싱한다.
// 모든 읽기는 경계 검사를 거친다 — 손상/기형 파일에서도 크래시 없이 에러/경고를 반환하는 것이 목표.
//
// 구현 파일 구성:
//   PeFile.cpp        로드, 파싱 순서
//   PeHeaders.cpp     DOS / NT / File / Optional Header, Data Directory, DOS Stub
//   PeSections.cpp    Section Table, RVA ↔ 파일 오프셋 매핑, 메모리 이미지 관점 읽기
//   PeDirectories.cpp Import / Export 파싱, 구조 위치(Region) 기록
//   PeRelocs.cpp      Base Relocation 블록 파싱
class PeFile {
public:
    // ======================================================================
    // 로드 (PeFile.cpp)
    // ======================================================================
    // 성공 시 true, 실패 시 false + error()에 사유.
    bool load(const std::filesystem::path& path);
    bool loadFromMemory(std::vector<uint8_t> data);

    const std::string& error() const { return error_; }
    const std::vector<uint8_t>& raw() const { return data_; }
    // 파싱은 성공했지만 스펙과 다른 점 (헤더 겹침, 비표준 디렉터리 개수 등)
    const std::vector<std::string>& warnings() const { return warnings_; }

    // 경계 검사 포함 읽기 (파일 오프셋 기준)
    template <typename T>
    bool read(uint64_t offset, T& out) const {
        if (offset > data_.size() || data_.size() - offset < sizeof(T)) return false;
        std::memcpy(&out, data_.data() + offset, sizeof(T));
        return true;
    }

    // ======================================================================
    // 헤더 (PeHeaders.cpp)
    // ======================================================================
    const DosHeader& dosHeader() const { return dos_; }

    // DOS Stub: DOS Header 직후(0x40) ~ e_lfanew 직전. Windows 로더는 사용하지 않는 영역.
    // (MSVC 산출물은 이 안에 Rich Header도 포함)
    static constexpr uint64_t dosStubOffset() { return sizeof(DosHeader); }
    uint32_t dosStubSize() const;              // e_lfanew <= 0x40 이면 0
    std::span<const uint8_t> dosStub() const;  // Stub 원본 바이트
    std::string dosStubMessage() const;        // "This program cannot be run in DOS mode." 등, 없으면 ""

    uint32_t ntSignature() const { return ntSignature_; }
    const FileHeader& fileHeader() const { return fileHeader_; }
    bool is64() const { return is64_; }
    const OptionalHeader32& optionalHeader32() const { return opt32_; }
    const OptionalHeader64& optionalHeader64() const { return opt64_; }

    // 표준 16개: NumberOfRvaAndSizes 만큼 (로더와 동일). 16개 초과분(index >= 16)은 스펙 외 —
    // SizeOfOptionalHeader 안에 들어가는 것만, Windows 로더는 무시하지만 분석용으로 노출한다.
    const std::vector<DataDirectory>& dataDirectories() const { return dataDirs_; }
    static constexpr bool isStandardDataDirectory(size_t index) { return index < kNumDataDirectories; }

    // 각 헤더 구조의 파일 오프셋 (GUI Offset 컬럼 표시용)
    uint64_t ntHeadersOffset() const { return ntOffset_; }
    uint64_t fileHeaderOffset() const { return ntOffset_ + 4; }
    uint64_t optionalHeaderOffset() const { return fileHeaderOffset() + sizeof(FileHeader); }
    uint64_t dataDirectoriesOffset() const;

    // Optional Header 공통 필드 (PE32 / PE32+ 구분 없이)
    uint64_t imageBase() const { return is64_ ? opt64_.ImageBase : opt32_.ImageBase; }
    uint32_t entryPoint() const { return is64_ ? opt64_.AddressOfEntryPoint : opt32_.AddressOfEntryPoint; }
    uint32_t sizeOfHeaders() const { return is64_ ? opt64_.SizeOfHeaders : opt32_.SizeOfHeaders; }
    uint32_t sizeOfImage() const { return is64_ ? opt64_.SizeOfImage : opt32_.SizeOfImage; }
    uint32_t sectionAlignment() const { return is64_ ? opt64_.SectionAlignment : opt32_.SectionAlignment; }
    // SectionAlignment < 0x1000 이면 로더가 파일을 그대로 매핑 → RVA == File Offset
    bool isLowAlignment() const { return sectionAlignment() < 0x1000; }

    // ======================================================================
    // 섹션 / 주소 매핑 (PeSections.cpp)
    // ======================================================================
    const std::vector<SectionHeader>& sections() const { return sections_; }
    uint64_t sectionTableOffset() const { return optionalHeaderOffset() + fileHeader_.SizeOfOptionalHeader; }

    // 주소가 속한 섹션 인덱스 (없으면 nullopt)
    std::optional<size_t> sectionIndexForRva(uint32_t rva) const;
    std::optional<size_t> sectionIndexForOffset(uint64_t offset) const;  // 디스크상 Raw 데이터 범위 기준

    // 메모리 이미지 관점 읽기 (로더가 매핑한 모습: 파일에 없는 매핑 영역은 0)
    struct RvaSpan {
        bool mapped = false;                 // 이미지에 매핑된 주소인가
        std::optional<uint64_t> fileOffset;  // 파일 바이트가 있으면 그 위치 (없으면 0으로 채워진 가상 영역)
        uint64_t length = 0;                 // 같은 성질이 이어지는 바이트 수
    };
    RvaSpan spanAtRva(uint32_t rva) const;
    bool readRva(uint32_t rva, void* dst, size_t size) const;  // 매핑 안 된 바이트가 있으면 false
    template <typename T>
    bool readRva(uint32_t rva, T& out) const { return readRva(rva, &out, sizeof(T)); }

    // RVA → 파일 오프셋 (파일에 실제 바이트가 있을 때만)
    std::optional<uint32_t> rvaToOffset(uint32_t rva) const;
    uint64_t fileOffsetOr(uint32_t rva) const;  // 파일 위치, 가상 영역이면 kNoFileOffset

    // RVA 위치의 NUL 종료 문자열 (매핑 불가 / maxLen 초과 시 nullopt)
    std::optional<std::string> readStringAtRva(uint32_t rva, size_t maxLen = 512) const;

    // VA(ImageBase 포함 절대 주소) → RVA. ImageBase 아래이거나 이미지에 매핑되지 않으면 nullopt
    std::optional<uint32_t> vaToRva(uint64_t va) const;

    // ======================================================================
    // 디렉터리 (PeDirectories.cpp)
    // ======================================================================
    // Import / Export (없으면 빈 vector / nullopt)
    const std::vector<ImportModule>& imports() const { return imports_; }
    const std::optional<ExportInfo>& exports() const { return exports_; }

    // Base Relocation (PeRelocs.cpp) — 없으면 빈 vector
    const std::vector<RelocBlock>& relocations() const { return relocs_; }

    // 파싱하며 확인한 구조들의 파일 위치 (Import/Export). 정렬되어 있지 않음.
    const std::vector<Region>& regions() const { return regions_; }

private:
    // --- 공통 (PeFile.cpp) ---
    bool parse();
    bool fail(std::string msg);
    void warn(std::string msg) { warnings_.push_back(std::move(msg)); }

    // 헤더 구조 읽기용: 파일 끝을 넘는 부분은 0으로 채운다 (로더 동작과 동일). 잘렸으면 headerTruncated_ 표시.
    template <typename T>
    void readPadded(uint64_t offset, T& out) {
        std::memset(&out, 0, sizeof(T));
        if (offset >= data_.size()) {
            headerTruncated_ = true;
            return;
        }
        const size_t n = static_cast<size_t>(std::min<uint64_t>(sizeof(T), data_.size() - offset));
        std::memcpy(&out, data_.data() + offset, n);
        if (n < sizeof(T)) headerTruncated_ = true;
    }

    // --- 헤더 (PeHeaders.cpp) ---
    bool parseHeaders();         // DOS → NT → File → Optional → Data Directories. PE 가 아니면 false
    void parseDataDirectories();

    // --- 섹션 (PeSections.cpp) ---
    void parseSectionTable();

    // --- 디렉터리 (PeDirectories.cpp) — 실패해도 전체 파싱을 중단하지 않고 warnings_ 에 기록 ---
    void parseImports();
    void parseExports();
    const DataDirectory* directory(size_t index) const;  // 없으면 nullptr
    void addRegion(RegionKind kind, uint64_t offset, uint64_t size, std::string label);
    void addRvaRegion(RegionKind kind, uint32_t rva, uint64_t size, std::string label);  // RVA 변환 실패 시 무시

    // --- Base Relocation (PeRelocs.cpp) ---
    void parseRelocations();

    // --- 데이터 ---
    std::vector<uint8_t> data_;
    std::string error_;
    std::vector<std::string> warnings_;
    bool headerTruncated_ = false;

    // 헤더
    DosHeader dos_{};
    uint64_t ntOffset_ = 0;
    uint32_t ntSignature_ = 0;
    FileHeader fileHeader_{};
    bool is64_ = false;
    OptionalHeader32 opt32_{};
    OptionalHeader64 opt64_{};
    std::vector<DataDirectory> dataDirs_;

    // 섹션
    std::vector<SectionHeader> sections_;

    // 디렉터리
    std::vector<ImportModule> imports_;
    std::optional<ExportInfo> exports_;
    std::vector<RelocBlock> relocs_;
    std::vector<Region> regions_;
};

}  // namespace pe
