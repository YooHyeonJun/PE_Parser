#pragma once
// PE 포맷 구조체 정의 (winnt.h 의존 없이 직접 정의 — 플랫폼 독립 + Qt와 windows.h 매크로 충돌 회피)
// 참고: https://learn.microsoft.com/windows/win32/debug/pe-format

#include <cstdint>

namespace pe {

constexpr uint16_t kDosSignature = 0x5A4D;      // "MZ"
constexpr uint32_t kNtSignature = 0x00004550;   // "PE\0\0"
constexpr uint16_t kOptMagicPe32 = 0x010B;
constexpr uint16_t kOptMagicPe32Plus = 0x020B;
constexpr uint32_t kNumDataDirectories = 16;

#pragma pack(push, 1)

struct DosHeader {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    int32_t e_lfanew;
};
static_assert(sizeof(DosHeader) == 64);

struct FileHeader {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};
static_assert(sizeof(FileHeader) == 20);

struct DataDirectory {
    uint32_t VirtualAddress;
    uint32_t Size;
};
static_assert(sizeof(DataDirectory) == 8);

struct OptionalHeader32 {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    DataDirectory DataDirectory[kNumDataDirectories];
};
static_assert(sizeof(OptionalHeader32) == 224);

struct OptionalHeader64 {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    DataDirectory DataDirectory[kNumDataDirectories];
};
static_assert(sizeof(OptionalHeader64) == 240);

struct SectionHeader {
    char Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};
static_assert(sizeof(SectionHeader) == 40);

// Data Directory #1 (Import): 이 구조체 배열이 이어진다.
// 스펙상 모든 필드가 0인 항목으로 끝나지만, 실제 로더는 Name 또는 FirstThunk 가 0 이면 끝으로 본다.
struct ImportDescriptor {
    uint32_t OriginalFirstThunk;  // ILT(Import Lookup Table) RVA — 함수 이름/Ordinal 목록 (원본)
    uint32_t TimeDateStamp;       // 0: 바인딩 안 됨, -1: 새 방식 바인딩
    uint32_t ForwarderChain;
    uint32_t Name;                // DLL 이름 문자열 RVA
    uint32_t FirstThunk;          // IAT(Import Address Table) RVA — 로드 시 실제 함수 주소로 덮어써짐
};
static_assert(sizeof(ImportDescriptor) == 20);

// Data Directory #0 (Export)
struct ExportDirectory {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t Name;                   // DLL 이름 문자열 RVA
    uint32_t Base;                   // 시작 Ordinal 번호
    uint32_t NumberOfFunctions;      // AddressOfFunctions 배열 길이
    uint32_t NumberOfNames;          // AddressOfNames / AddressOfNameOrdinals 배열 길이
    uint32_t AddressOfFunctions;     // uint32_t[NumberOfFunctions] : 함수 RVA
    uint32_t AddressOfNames;         // uint32_t[NumberOfNames]     : 이름 문자열 RVA (알파벳순)
    uint32_t AddressOfNameOrdinals;  // uint16_t[NumberOfNames]     : AddressOfFunctions 인덱스
};
static_assert(sizeof(ExportDirectory) == 40);

// Data Directory #5 (Base Relocation): 이 블록 헤더 + WORD 항목 배열이 연달아 이어진다.
//   항목 WORD = 상위 4비트 Type | 하위 12비트 Offset (블록 VirtualAddress 기준)
struct BaseRelocationBlock {
    uint32_t VirtualAddress;  // 이 블록이 다루는 4KB 페이지의 RVA
    uint32_t SizeOfBlock;     // 헤더(8) + 항목 배열 바이트 수
};
static_assert(sizeof(BaseRelocationBlock) == 8);

#pragma pack(pop)

// Base Relocation 항목 Type
constexpr uint8_t kRelocAbsolute = 0;  // 패딩 (무시)
constexpr uint8_t kRelocHigh = 1;      // 16비트: delta 상위 16비트
constexpr uint8_t kRelocLow = 2;       // 16비트: delta 하위 16비트
constexpr uint8_t kRelocHighLow = 3;   // 32비트 전체 (PE32 표준)
constexpr uint8_t kRelocHighAdj = 4;   // 상위 16비트 + 다음 항목을 하위 16비트 파라미터로 사용
constexpr uint8_t kRelocDir64 = 10;    // 64비트 전체 (PE32+ 표준)

// Data Directory 인덱스
constexpr size_t kDirExport = 0;
constexpr size_t kDirImport = 1;
constexpr size_t kDirBaseReloc = 5;

// ILT/IAT 항목의 최상위 비트가 1이면 이름이 아니라 Ordinal로 import
constexpr uint32_t kOrdinalFlag32 = 0x80000000u;
constexpr uint64_t kOrdinalFlag64 = 0x8000000000000000ull;

}  // namespace pe
