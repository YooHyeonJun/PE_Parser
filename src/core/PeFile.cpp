#include "core/PeFile.h"

#include <algorithm>
#include <fstream>
#include <iterator>

namespace pe {

namespace {
constexpr uint64_t kMaxFileSize = 1ull << 31;  // 2GB 상한 (일단 전체 로드 방식)
constexpr uint16_t kMaxSections = 96;          // Windows 로더 제한과 동일
}  // namespace

bool PeFile::fail(std::string msg) {
    error_ = std::move(msg);
    return false;
}

bool PeFile::load(const std::filesystem::path& path) {
    std::error_code ec;
    const auto size = std::filesystem::file_size(path, ec);
    if (ec) return fail("파일 크기를 읽을 수 없습니다: " + ec.message());
    if (size > kMaxFileSize) return fail("파일이 너무 큽니다 (2GB 초과).");

    std::ifstream in(path, std::ios::binary);
    if (!in) return fail("파일을 열 수 없습니다.");

    std::vector<uint8_t> buf(static_cast<size_t>(size));
    if (size > 0 && !in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(size)))
        return fail("파일 읽기에 실패했습니다.");

    return loadFromMemory(std::move(buf));
}

bool PeFile::loadFromMemory(std::vector<uint8_t> data) {
    *this = PeFile{};
    data_ = std::move(data);
    return parse();
}

bool PeFile::parse() {
    // 1) DOS Header
    if (!read(0, dos_)) return fail("DOS 헤더보다 파일이 작습니다.");
    if (dos_.e_magic != kDosSignature) return fail("MZ 시그니처가 없습니다 (PE 파일 아님).");
    if (dos_.e_lfanew < 0) return fail("e_lfanew 값이 음수입니다.");

    // 2) NT Signature
    ntOffset_ = static_cast<uint32_t>(dos_.e_lfanew);
    if (!read(ntOffset_, ntSignature_)) return fail("e_lfanew가 파일 범위를 벗어납니다.");
    if (ntSignature_ != kNtSignature) return fail("PE 시그니처(PE\\0\\0)가 없습니다.");

    // 3) File Header
    if (!read(fileHeaderOffset(), fileHeader_)) return fail("File Header가 잘렸습니다.");
    if (fileHeader_.NumberOfSections > kMaxSections) return fail("섹션 개수가 비정상적으로 많습니다.");

    // 4) Optional Header — Magic으로 PE32 / PE32+ 판별
    const uint64_t optOff = optionalHeaderOffset();
    uint16_t magic = 0;
    if (fileHeader_.SizeOfOptionalHeader < sizeof(uint16_t) || !read(optOff, magic))
        return fail("Optional Header가 없습니다.");

    // SizeOfOptionalHeader가 구조체보다 작을 수 있으므로 가능한 만큼만 복사하고 나머지는 0
    auto copyPartial = [&](auto& dst) {
        const uint64_t avail = optOff < data_.size() ? data_.size() - optOff : 0;
        const size_t n = static_cast<size_t>(
            std::min<uint64_t>({sizeof(dst), fileHeader_.SizeOfOptionalHeader, avail}));
        std::memcpy(&dst, data_.data() + optOff, n);
    };

    uint32_t numRva = 0;
    size_t dirFieldOffset = 0;
    if (magic == kOptMagicPe32) {
        is64_ = false;
        copyPartial(opt32_);
        numRva = opt32_.NumberOfRvaAndSizes;
        dirFieldOffset = offsetof(OptionalHeader32, DataDirectory);
    } else if (magic == kOptMagicPe32Plus) {
        is64_ = true;
        copyPartial(opt64_);
        numRva = opt64_.NumberOfRvaAndSizes;
        dirFieldOffset = offsetof(OptionalHeader64, DataDirectory);
    } else {
        return fail("알 수 없는 Optional Header Magic 값입니다.");
    }

    // 5) Data Directories — NumberOfRvaAndSizes 와 SizeOfOptionalHeader 둘 다로 제한
    uint32_t maxBySize = fileHeader_.SizeOfOptionalHeader > dirFieldOffset
                             ? static_cast<uint32_t>((fileHeader_.SizeOfOptionalHeader - dirFieldOffset) /
                                                     sizeof(DataDirectory))
                             : 0;
    const uint32_t numDirs = std::min({numRva, kNumDataDirectories, maxBySize});
    const DataDirectory* dirs = is64_ ? opt64_.DataDirectory : opt32_.DataDirectory;
    dataDirs_.assign(dirs, dirs + numDirs);

    // 6) Section Table
    uint64_t secOff = sectionTableOffset();
    sections_.reserve(fileHeader_.NumberOfSections);
    for (uint16_t i = 0; i < fileHeader_.NumberOfSections; ++i) {
        SectionHeader sh{};
        if (!read(secOff + i * sizeof(SectionHeader), sh)) return fail("섹션 테이블이 잘렸습니다.");
        sections_.push_back(sh);
    }

    // TODO: Import / Export / Resource / Relocation / TLS / Debug 디렉터리 파싱
    return true;
}

uint64_t PeFile::dataDirectoriesOffset() const {
    return optionalHeaderOffset() +
           (is64_ ? offsetof(OptionalHeader64, DataDirectory) : offsetof(OptionalHeader32, DataDirectory));
}

std::optional<uint32_t> PeFile::rvaToOffset(uint32_t rva) const {
    const uint32_t sizeOfHeaders = is64_ ? opt64_.SizeOfHeaders : opt32_.SizeOfHeaders;
    if (rva < sizeOfHeaders) return rva;  // 헤더 영역은 RVA == 파일 오프셋

    for (const auto& s : sections_) {
        const uint32_t span = std::max(s.VirtualSize, s.SizeOfRawData);
        if (rva >= s.VirtualAddress && rva - s.VirtualAddress < span) {
            const uint32_t delta = rva - s.VirtualAddress;
            if (delta >= s.SizeOfRawData) return std::nullopt;  // 디스크에 없는 영역(.bss 등)
            return s.PointerToRawData + delta;
        }
    }
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// 표시용 헬퍼
// ---------------------------------------------------------------------------

std::string sectionName(const SectionHeader& s) {
    return std::string(s.Name, strnlen(s.Name, sizeof(s.Name)));
}

const char* machineToString(uint16_t m) {
    switch (m) {
        case 0x014C: return "x86 (I386)";
        case 0x8664: return "x64 (AMD64)";
        case 0xAA64: return "ARM64";
        case 0x01C4: return "ARMNT";
        case 0x0200: return "IA64";
        case 0x0000: return "Unknown";
        default: return "Other";
    }
}

const char* subsystemToString(uint16_t s) {
    switch (s) {
        case 1: return "Native";
        case 2: return "Windows GUI";
        case 3: return "Windows CUI";
        case 9: return "Windows CE GUI";
        case 10: return "EFI Application";
        case 11: return "EFI Boot Service Driver";
        case 12: return "EFI Runtime Driver";
        case 14: return "Xbox";
        case 16: return "Windows Boot Application";
        default: return "Unknown";
    }
}

const char* dataDirectoryName(size_t i) {
    static const char* kNames[kNumDataDirectories] = {
        "Export",        "Import",       "Resource",     "Exception",
        "Security",      "Base Reloc",   "Debug",        "Architecture",
        "Global Ptr",    "TLS",          "Load Config",  "Bound Import",
        "IAT",           "Delay Import", "COM Descriptor", "Reserved"};
    return i < kNumDataDirectories ? kNames[i] : "?";
}

namespace {
template <typename T>
struct Flag {
    T bit;
    const char* name;
};

template <typename T, size_t N>
std::string flagsToString(T value, const Flag<T> (&table)[N]) {
    std::string out;
    for (const auto& [bit, name] : table) {
        if (value & bit) {
            if (!out.empty()) out += " | ";
            out += name;
        }
    }
    return out;
}
}  // namespace

std::string fileCharacteristicsToString(uint16_t c) {
    static const Flag<uint16_t> kFlags[] = {
        {0x0001, "RELOCS_STRIPPED"}, {0x0002, "EXECUTABLE_IMAGE"},
        {0x0020, "LARGE_ADDRESS_AWARE"}, {0x0100, "32BIT_MACHINE"},
        {0x0200, "DEBUG_STRIPPED"}, {0x1000, "SYSTEM"}, {0x2000, "DLL"}};
    return flagsToString(c, kFlags);
}

std::string sectionCharacteristicsToString(uint32_t c) {
    static const Flag<uint32_t> kFlags[] = {
        {0x00000020, "CODE"}, {0x00000040, "INITIALIZED_DATA"}, {0x00000080, "UNINITIALIZED_DATA"},
        {0x02000000, "DISCARDABLE"}, {0x10000000, "SHARED"}, {0x20000000, "EXECUTE"},
        {0x40000000, "READ"}, {0x80000000, "WRITE"}};
    return flagsToString(c, kFlags);
}

}  // namespace pe
