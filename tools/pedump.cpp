// core 라이브러리 단독 검증용 콘솔 도구 (Qt 비의존)
// 사용법: pedump <file>
#include "core/PeFile.h"

#include <cstdio>

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: pedump <file>\n");
        return 1;
    }

    pe::PeFile pe;
    if (!pe.load(argv[1])) {
        std::fprintf(stderr, "error: %s\n", pe.error().c_str());
        return 2;
    }

    const auto& fh = pe.fileHeader();
    std::printf("Format       : %s\n", pe.is64() ? "PE32+" : "PE32");
    std::printf("Machine      : 0x%04X (%s)\n", fh.Machine, pe::machineToString(fh.Machine));
    std::printf("Sections     : %u\n", fh.NumberOfSections);
    std::printf("ImageBase    : 0x%llX\n", static_cast<unsigned long long>(pe.imageBase()));
    std::printf("EntryPoint   : 0x%08X\n", pe.entryPoint());
    std::printf("Characteristics: %s\n\n", pe::fileCharacteristicsToString(fh.Characteristics).c_str());

    std::printf("%-10s %-10s %-10s %-10s %-10s\n", "Name", "VA", "VSize", "RawPtr", "RawSize");
    for (const auto& s : pe.sections()) {
        std::printf("%-10s 0x%08X 0x%08X 0x%08X 0x%08X\n", pe::sectionName(s).c_str(), s.VirtualAddress,
                    s.VirtualSize, s.PointerToRawData, s.SizeOfRawData);
    }

    std::printf("\n%-16s %-10s %-10s\n", "Directory", "RVA", "Size");
    const auto& dirs = pe.dataDirectories();
    for (size_t i = 0; i < dirs.size(); ++i) {
        if (dirs[i].VirtualAddress == 0 && dirs[i].Size == 0) continue;
        std::printf("%-16s 0x%08X 0x%08X\n", pe::dataDirectoryName(i), dirs[i].VirtualAddress, dirs[i].Size);
    }
    return 0;
}
