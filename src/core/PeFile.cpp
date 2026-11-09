// 로드 + 파싱 순서 조율. 실제 파싱은 단계별 파일에 있다.
//   헤더 → PeHeaders.cpp / 섹션 → PeSections.cpp / Import·Export → PeDirectories.cpp
#include "core/PeFile.h"

#include <cstdio>
#include <fstream>

namespace pe {

namespace {
constexpr uint64_t kMaxFileSize = 1ull << 31;  // 2GB 상한 (일단 전체 로드 방식)
}  // namespace

bool PeFile::fail(std::string msg) {
    error_ = std::move(msg);
    return false;
}

bool PeFile::load(const std::filesystem::path& path) {
    std::error_code ec;
    //Check the file size
    const auto size = std::filesystem::file_size(path, ec);
    if (ec) return fail("파일 크기를 읽을 수 없습니다: " + ec.message());
    if (size > kMaxFileSize) return fail("파일이 너무 큽니다 (2GB 초과).");

    //Generating Object and open file with binar mode
    std::ifstream in(path, std::ios::binary);
    if (!in) return fail("파일을 열 수 없습니다.");

    //Make buffer for file(size with file size)
    //static_cast -> 타입 맞춤용 vector 생성자는 size_t를 받기 때문
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

// ---------------------------------------------------------------------------
// 파싱 순서 — Windows 로더와 같은 관점으로 읽는다.
//  1) 헤더 (PE 가 아니면 여기서만 실패)
//  2) 섹션 테이블
//  3) 헤더/섹션 공통 경고
//  4) Data Directory 내용 — 실패해도 헤더 정보는 보여줄 수 있도록 경고만 남긴다
// ---------------------------------------------------------------------------

bool PeFile::parse() {
    if (!parseHeaders()) return false;
    parseSectionTable();

    if (headerTruncated_) warn("헤더 일부가 파일 끝을 넘어갑니다 — 넘는 부분은 0으로 간주합니다 (로더와 동일).");
    if (isLowAlignment()) {
        char b[16];
        std::snprintf(b, sizeof b, "%X", sectionAlignment());
        warn(std::string("SectionAlignment(0x") + b +
             ") < 0x1000: Low-alignment 모드 — 파일이 그대로 매핑되어 RVA == File Offset 입니다.");
    }

    parseImports();
    parseExports();
    // TODO: Resource / Relocation / TLS / Debug 디렉터리 파싱
    return true;
}

}  // namespace pe
