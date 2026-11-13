// core 라이브러리 단독 검증용 콘솔 도구 (Qt 비의존)
// 사용법: pedump <file> [--regions | --stats]
//   --regions : 파싱한 구조의 파일 위치 목록만 출력 (offset<TAB>size<TAB>kind<TAB>label)
//   --stats   : 집계값 한 줄 + 경고 (대량 검증용)
#include "core/PeFile.h"
#include "core/PeFormat.h"

#include <cstdio>
#include <cwchar>

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: pedump <file> [--regions]\n");
        return 1;
    }
    const bool regionsOnly = argc >= 3 && std::wcscmp(argv[2], L"--regions") == 0;
    const bool statsOnly = argc >= 3 && std::wcscmp(argv[2], L"--stats") == 0;

    pe::PeFile pe;
    if (!pe.load(argv[1])) {
        std::fprintf(stderr, "error: %s\n", pe.error().c_str());
        return 2;
    }

    if (regionsOnly) {
        for (const auto& r : pe.regions())
            std::printf("%llu\t%llu\t%s\t%s\n", static_cast<unsigned long long>(r.offset),
                        static_cast<unsigned long long>(r.size), pe::regionKindName(r.kind), r.label.c_str());
        return 0;
    }

    if (statsOnly) {
        // 외부 도구(dumpbin 등)와 비교하기 위한 집계값 한 줄: key=value
        size_t impFuncs = 0, expEntries = 0, relocEntries = 0;
        for (const auto& m : pe.imports()) impFuncs += m.functions.size();
        if (const auto& exp = pe.exports())
            for (const auto& f : exp->functions) {
                size_t names = 1;
                for (size_t p = f.name.find(" / "); p != std::string::npos; p = f.name.find(" / ", p + 3)) ++names;
                expEntries += names;  // 이름 없는 함수 1줄, 별칭은 이름마다 1줄 (dumpbin 표기와 동일)
            }
        for (const auto& b : pe.relocations()) relocEntries += b.entries.size();
        std::printf("sections=%zu impDlls=%zu impFuncs=%zu expEntries=%zu relocBlocks=%zu relocEntries=%zu warnings=%zu\n",
                    pe.sections().size(), pe.imports().size(), impFuncs, expEntries, pe.relocations().size(),
                    relocEntries, pe.warnings().size());
        for (const auto& w : pe.warnings()) std::printf("WARNING: %s\n", w.c_str());
        return 0;
    }

    const auto& fh = pe.fileHeader();
    std::printf("Format       : %s\n", pe.is64() ? "PE32+" : "PE32");
    std::printf("Machine      : 0x%04X (%s)\n", fh.Machine, pe::machineToString(fh.Machine));
    std::printf("Sections     : %u\n", fh.NumberOfSections);
    std::printf("ImageBase    : 0x%llX\n", static_cast<unsigned long long>(pe.imageBase()));
    std::printf("EntryPoint   : 0x%08X\n", pe.entryPoint());
    std::printf("Characteristics: %s\n", pe::fileCharacteristicsToString(fh.Characteristics).c_str());
    std::printf("DOS Stub     : offset 0x%llX, %u bytes, message \"%s\"\n\n",
                static_cast<unsigned long long>(pe.dosStubOffset()), pe.dosStubSize(), pe.dosStubMessage().c_str());

    std::printf("%-10s %-10s %-10s %-10s %-10s\n", "Name", "VA", "VSize", "RawPtr", "RawSize");
    for (const auto& s : pe.sections()) {
        std::printf("%-10s 0x%08X 0x%08X 0x%08X 0x%08X\n", pe::sectionName(s).c_str(), s.VirtualAddress,
                    s.VirtualSize, s.PointerToRawData, s.SizeOfRawData);
    }

    const auto& dirs = pe.dataDirectories();
    std::printf("\nData Directories: %zu\n", dirs.size());
    std::printf("%-3s %-16s %-10s %-10s\n", "#", "Directory", "RVA", "Size");
    for (size_t i = 0; i < dirs.size(); ++i) {
        if (dirs[i].VirtualAddress == 0 && dirs[i].Size == 0) continue;
        std::printf("%-3zu %-16s 0x%08X 0x%08X\n", i,
                    pe::PeFile::isStandardDataDirectory(i) ? pe::dataDirectoryName(i) : "(non-standard)",
                    dirs[i].VirtualAddress, dirs[i].Size);
    }

    // Imports: DLL 별 함수 수 + 앞의 몇 개
    const auto& imports = pe.imports();
    std::printf("\nImports: %zu DLLs\n", imports.size());
    for (const auto& m : imports) {
        std::printf("  %-40s %4zu funcs  ", m.dllName.c_str(), m.functions.size());
        for (size_t i = 0; i < m.functions.size() && i < 3; ++i) {
            const auto& f = m.functions[i];
            if (f.byOrdinal)
                std::printf("#%u ", f.ordinal);
            else
                std::printf("%s ", f.name.c_str());
        }
        std::printf("%s\n", m.functions.size() > 3 ? "..." : "");
    }

    // Exports
    if (const auto& exp = pe.exports()) {
        size_t fwd = 0, noName = 0;
        for (const auto& f : exp->functions) {
            fwd += !f.forwarder.empty();
            noName += f.name.empty();
        }
        std::printf("\nExports: %s, %zu funcs (ordinal-only %zu, forwarded %zu), base %u\n", exp->dllName.c_str(),
                    exp->functions.size(), noName, fwd, exp->directory.Base);
        for (size_t i = 0; i < exp->functions.size() && i < 8; ++i) {
            const auto& f = exp->functions[i];
            std::printf("  %5u 0x%08X %s%s%s\n", f.ordinal, f.rva, f.name.empty() ? "(ordinal only)" : f.name.c_str(),
                        f.forwarder.empty() ? "" : " -> ", f.forwarder.c_str());
        }
        if (exp->functions.size() > 8) std::printf("  ...\n");
    }

    // Base Relocation
    if (const auto& relocs = pe.relocations(); !relocs.empty()) {
        size_t total = 0;
        for (const auto& b : relocs) total += b.entries.size();
        std::printf("\nRelocations: %zu blocks, %zu entries\n", relocs.size(), total);
        for (size_t i = 0; i < relocs.size() && i < 4; ++i) {
            const auto& b = relocs[i];
            std::printf("  page 0x%08X  %4zu entries ", b.header.VirtualAddress, b.entries.size());
            for (size_t j = 0; j < b.entries.size() && j < 3; ++j)
                std::printf(" %s+0x%03X", pe::relocTypeToString(b.entries[j].type, pe.fileHeader().Machine),
                            b.entries[j].offset);
            std::printf("\n");
        }
        if (relocs.size() > 4) std::printf("  ...\n");
    }

    for (const auto& w : pe.warnings()) std::printf("\nWARNING: %s", w.c_str());
    if (!pe.warnings().empty()) std::printf("\n");
    return 0;
}
