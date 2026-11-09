#pragma once
// 파싱 결과를 사람이 읽는 문자열로 바꾸는 표시용 헬퍼 (파싱 로직과 분리)

#include "core/PeFile.h"

#include <cstdint>
#include <string>

namespace pe {

std::string sectionName(const SectionHeader& s);  // 8바이트 꽉 찬 이름(NUL 없음)도 안전하게
const char* machineToString(uint16_t machine);
const char* subsystemToString(uint16_t subsystem);
const char* dataDirectoryName(size_t index);
const char* regionKindName(RegionKind kind);
std::string fileCharacteristicsToString(uint16_t c);
std::string sectionCharacteristicsToString(uint32_t c);

}  // namespace pe
