#pragma once

#include "core/PeTypes.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace pe {

// PE 파일 하나를 메모리에 올려 헤더들을 파싱한다.
// 모든 읽기는 경계 검사(bounds check)를 거친다 — 손상/악성 파일에서도 크래시 없이 에러를 반환하는 것이 목표.
class PeFile {
public:
    // 성공 시 true, 실패 시 false + error()에 사유.
    bool load(const std::filesystem::path& path);
    bool loadFromMemory(std::vector<uint8_t> data);

    const std::string& error() const { return error_; }
    const std::vector<uint8_t>& raw() const { return data_; }

    // --- 헤더 접근 ---
    const DosHeader& dosHeader() const { return dos_; }
    uint32_t ntSignature() const { return ntSignature_; }
    const FileHeader& fileHeader() const { return fileHeader_; }
    bool is64() const { return is64_; }
    const OptionalHeader32& optionalHeader32() const { return opt32_; }
    const OptionalHeader64& optionalHeader64() const { return opt64_; }
    const std::vector<DataDirectory>& dataDirectories() const { return dataDirs_; }
    const std::vector<SectionHeader>& sections() const { return sections_; }

    // --- 각 구조체의 파일 오프셋 (GUI에서 Offset 컬럼 표시용) ---
    uint64_t ntHeadersOffset() const { return ntOffset_; }
    uint64_t fileHeaderOffset() const { return ntOffset_ + 4; }
    uint64_t optionalHeaderOffset() const { return fileHeaderOffset() + sizeof(FileHeader); }
    uint64_t dataDirectoriesOffset() const;
    uint64_t sectionTableOffset() const { return optionalHeaderOffset() + fileHeader_.SizeOfOptionalHeader; }

    // 공통 필드 편의 함수
    uint64_t imageBase() const { return is64_ ? opt64_.ImageBase : opt32_.ImageBase; }
    uint32_t entryPoint() const { return is64_ ? opt64_.AddressOfEntryPoint : opt32_.AddressOfEntryPoint; }

    // RVA -> 파일 오프셋 변환 (Import/Export 등 디렉터리 파싱의 기반)
    std::optional<uint32_t> rvaToOffset(uint32_t rva) const;

    // 경계 검사 포함 읽기
    template <typename T>
    bool read(uint64_t offset, T& out) const {
        if (offset > data_.size() || data_.size() - offset < sizeof(T)) return false;
        std::memcpy(&out, data_.data() + offset, sizeof(T));
        return true;
    }

private:
    bool parse();
    bool fail(std::string msg);

    std::vector<uint8_t> data_;
    std::string error_;

    DosHeader dos_{};
    uint64_t ntOffset_ = 0;
    uint32_t ntSignature_ = 0;
    FileHeader fileHeader_{};
    bool is64_ = false;
    OptionalHeader32 opt32_{};
    OptionalHeader64 opt64_{};
    std::vector<DataDirectory> dataDirs_;
    std::vector<SectionHeader> sections_;
};

// --- 표시용 헬퍼 ---
std::string sectionName(const SectionHeader& s);
const char* machineToString(uint16_t machine);
const char* subsystemToString(uint16_t subsystem);
const char* dataDirectoryName(size_t index);
std::string fileCharacteristicsToString(uint16_t c);
std::string sectionCharacteristicsToString(uint32_t c);

}  // namespace pe
