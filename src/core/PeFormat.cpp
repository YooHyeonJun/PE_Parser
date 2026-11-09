#include "core/PeFormat.h"

namespace pe {

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

const char* regionKindName(RegionKind k) {
    switch (k) {
        case RegionKind::ImportDescriptor: return "Import Descriptor";
        case RegionKind::ImportLookupTable: return "ILT";
        case RegionKind::ImportAddressTable: return "IAT";
        case RegionKind::ImportHintName: return "Hint/Name";
        case RegionKind::DllName: return "DLL Name";
        case RegionKind::ExportDirectory: return "Export Directory";
        case RegionKind::ExportAddressTable: return "Export Address Table";
        case RegionKind::ExportNameTable: return "Export Name Table";
        case RegionKind::ExportOrdinalTable: return "Export Ordinal Table";
        case RegionKind::ExportName: return "Export Name";
        case RegionKind::ExportForwarder: return "Forwarder";
    }
    return "?";
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
