// 헤더 파싱: DOS Header → NT Signature → File Header → Optional Header → Data Directories, DOS Stub
//
// 로더 관점 규칙
//  * 헤더가 파일 끝을 넘으면 넘는 부분은 0 (로더도 0으로 채워 매핑) → readPadded()
//  * Optional Header 는 SizeOfOptionalHeader 와 무관하게 고정 위치에서 읽는다
//    (SizeOfOptionalHeader 는 섹션 테이블 위치 계산에만 쓰임 → 0 이면 헤더와 섹션 테이블이 겹침)
//  * 진짜로 PE 가 아닌 경우(MZ 없음 / PE 시그니처 없음)만 실패로 처리하고, 나머지 이상은 경고
#include "core/PeFile.h"

#include <cstdio>

namespace pe {

namespace {
constexpr uint16_t kMaxSectionsXP = 96;  // XP 로더 제한 (Vista/7+ 는 65535 까지 허용)
constexpr uint16_t kMachineAmd64 = 0x8664;
constexpr uint16_t kMachineArm64 = 0xAA64;
constexpr uint16_t kMachineIa64 = 0x0200;
constexpr uint16_t kZmSignature = 0x4D5A;  // "ZM" — DOS 실행 파일 변형
constexpr uint16_t kNeSignature = 0x454E;  // "NE" — 16비트 Windows
constexpr uint16_t kLeSignature = 0x454C;  // "LE" — VxD
constexpr uint16_t kLxSignature = 0x584C;  // "LX" — OS/2

std::string hex4(uint16_t v) {
    char b[8];
    std::snprintf(b, sizeof b, "%04X", v);
    return b;
}
}  // namespace

bool PeFile::parseHeaders() {
    // 1) DOS Header (파일이 64바이트보다 작아도 0으로 채워 읽음 — 97바이트짜리 tiny PE 등)
    if (data_.size() < 2) return fail("파일이 너무 작습니다.");
    readPadded(0, dos_);
    if (dos_.e_magic == kZmSignature) return fail("'ZM' 시그니처: DOS 실행 파일입니다 (PE 아님).");
    if (dos_.e_magic != kDosSignature) return fail("MZ 시그니처가 없습니다 (PE 파일 아님).");
    if (data_.size() < sizeof(DosHeader)) warn("파일이 DOS Header(64바이트)보다 작습니다. 나머지는 0으로 간주합니다.");
    if (dos_.e_lfanew < 0) return fail("e_lfanew 값이 음수입니다.");

    // 2) NT Signature
    ntOffset_ = static_cast<uint32_t>(dos_.e_lfanew);
    if (ntOffset_ >= data_.size()) return fail("e_lfanew가 파일 범위를 벗어납니다.");
    readPadded(ntOffset_, ntSignature_);
    if (ntSignature_ != kNtSignature) {
        const uint16_t sig16 = static_cast<uint16_t>(ntSignature_);
        if (sig16 == kNeSignature) return fail("NE 시그니처: 16비트 Windows(NE) 실행 파일입니다 (PE 아님).");
        if (sig16 == kLeSignature || sig16 == kLxSignature)
            return fail("LE/LX 시그니처: OS/2·VxD 실행 파일입니다 (PE 아님).");
        return fail("PE 시그니처(PE\\0\\0)가 없습니다.");
    }
    if (dos_.e_lfanew < static_cast<int32_t>(sizeof(DosHeader)))
        warn("e_lfanew(" + std::to_string(dos_.e_lfanew) + ")가 DOS Header 안을 가리킵니다 — DOS/PE 헤더가 겹칩니다.");

    // 3) File Header
    readPadded(fileHeaderOffset(), fileHeader_);
    if (fileHeader_.NumberOfSections > kMaxSectionsXP)
        warn("섹션이 " + std::to_string(fileHeader_.NumberOfSections) + "개입니다 (XP 로더 한도 96, Vista/7+ 는 65535).");

    // 4) Optional Header — Magic 으로 PE32 / PE32+ 판별.
    const uint64_t optOff = optionalHeaderOffset();
    uint16_t magic = 0;
    readPadded(optOff, magic);
    if (magic == kOptMagicPe32) {
        is64_ = false;
    } else if (magic == kOptMagicPe32Plus) {
        is64_ = true;
    } else {
        // 이미지로는 로드 불가(데이터 파일로만 로드 가능)하지만 헤더는 보여준다
        const uint16_t m = fileHeader_.Machine;
        is64_ = (m == kMachineAmd64 || m == kMachineArm64 || m == kMachineIa64);
        warn("알 수 없는 Optional Header Magic(0x" + hex4(magic) + ") — 이미지로는 로드할 수 없는 파일입니다. Machine 기준 " +
             (is64_ ? "PE32+" : "PE32") + "로 해석합니다.");
    }
    if (is64_)
        readPadded(optOff, opt64_);
    else
        readPadded(optOff, opt32_);

    const uint16_t soh = fileHeader_.SizeOfOptionalHeader;
    if (soh < (is64_ ? sizeof(OptionalHeader64) : sizeof(OptionalHeader32)))
        warn("SizeOfOptionalHeader(" + std::to_string(soh) + ")가 표준 크기보다 작습니다 — Optional Header 뒷부분이 섹션 테이블과 겹칩니다.");

    // 5) Data Directories
    parseDataDirectories();
    return true;
}

void PeFile::parseDataDirectories() {
    //    표준 16개 범위: 로더처럼 NumberOfRvaAndSizes 만 따른다 (SizeOfOptionalHeader 무관, 파일 밖은 0).
    //    16개 초과(비표준): SizeOfOptionalHeader 안에 실제로 들어가는 만큼만 원본 버퍼에서 읽는다.
    const uint32_t numRva = is64_ ? opt64_.NumberOfRvaAndSizes : opt32_.NumberOfRvaAndSizes;
    const size_t dirFieldOffset = is64_ ? offsetof(OptionalHeader64, DataDirectory) : offsetof(OptionalHeader32, DataDirectory);
    const uint16_t soh = fileHeader_.SizeOfOptionalHeader;

    const uint32_t numStd = std::min(numRva, kNumDataDirectories);
    const uint32_t maxBySize =
        soh > dirFieldOffset ? static_cast<uint32_t>((soh - dirFieldOffset) / sizeof(DataDirectory)) : 0;
    const uint32_t numDirs = std::max(numStd, std::min(numRva, maxBySize));

    if (numRva > kNumDataDirectories && numRva > numDirs)
        warn("NumberOfRvaAndSizes(" + std::to_string(numRva) + ")가 비정상적으로 큽니다. " + std::to_string(numDirs) +
             "개만 읽습니다.");
    if (numDirs > kNumDataDirectories)
        warn("Data Directory가 " + std::to_string(numDirs) + "개입니다 (표준 16개). 확장 " +
             std::to_string(numDirs - kNumDataDirectories) + "개는 Windows 로더가 무시합니다.");

    //read numDirs entries from dataDirectoriesOffset() into dataDirs_
    const uint64_t dirOff = dataDirectoriesOffset();
    dataDirs_.resize(numDirs);
    for (uint32_t i = 0; i < numDirs; ++i) readPadded(dirOff + i * sizeof(DataDirectory), dataDirs_[i]);
}

uint64_t PeFile::dataDirectoriesOffset() const {
    return optionalHeaderOffset() +
           (is64_ ? offsetof(OptionalHeader64, DataDirectory) : offsetof(OptionalHeader32, DataDirectory));
}

// ---------------------------------------------------------------------------
// DOS Stub
// ---------------------------------------------------------------------------

uint32_t PeFile::dosStubSize() const {
    const auto lfanew = static_cast<uint32_t>(dos_.e_lfanew);  // parseHeaders()에서 음수는 이미 걸러짐
    return lfanew > dosStubOffset() ? lfanew - static_cast<uint32_t>(dosStubOffset()) : 0;
}

std::span<const uint8_t> PeFile::dosStub() const {
    const uint32_t size = dosStubSize();
    if (size == 0 || data_.size() < dosStubOffset() + size) return {};
    return {data_.data() + dosStubOffset(), size};
}

std::string PeFile::dosStubMessage() const {
    // DOS 출력 함수(INT 21h, AH=09h)는 '$'로 끝나는 문자열을 출력한다.
    // → Stub 안에서 '$' 직전까지 이어진 출력 가능 문자열 중 가장 긴 것을 메시지로 본다.
    const auto stub = dosStub();
    std::string best;
    size_t runStart = 0;
    bool inRun = false;

    for (size_t i = 0; i < stub.size(); ++i) {
        const uint8_t c = stub[i];
        if (c == '$') {
            if (inRun && i - runStart > best.size())
                best.assign(reinterpret_cast<const char*>(stub.data() + runStart), i - runStart);
            inRun = false;
            continue;
        }
        const bool printable = (c >= 0x20 && c < 0x7F) || c == '\r' || c == '\n';
        // "CD 21"(INT 21h)의 피연산자 0x21 은 '!' 로 보이지만 코드이므로 문자열 시작에서 제외
        const bool isIntOperand = i > 0 && stub[i - 1] == 0xCD;
        if (printable && !inRun && !isIntOperand) {
            inRun = true;
            runStart = i;
        } else if (!printable) {
            inRun = false;
        }
    }

    // 끝의 "\r\r\n" 등 제거
    while (!best.empty() && (best.back() == '\r' || best.back() == '\n' || best.back() == ' ')) best.pop_back();
    return best.size() >= 8 ? best : std::string{};  // 너무 짧으면 우연히 걸린 바이트로 간주
}

}  // namespace pe
