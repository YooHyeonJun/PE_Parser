cmake_minimum_required(VERSION 3.21)
project(PEParser VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    # 소스의 한글 문자열을 UTF-8로 해석 / 경고 수준 상향
    add_compile_options(/utf-8 /W4 /permissive-)
endif()

# ---------------------------------------------------------------------------
# core: Qt 비의존 PE 파싱 라이브러리
# ---------------------------------------------------------------------------
add_library(pecore STATIC
    src/core/PeTypes.h
    src/core/PeFile.h
    src/core/PeFile.cpp          # 로드 / 파싱 순서
    src/core/PeHeaders.cpp       # DOS / NT / File / Optional Header, Data Directory, DOS Stub
    src/core/PeSections.cpp      # Section Table, RVA ↔ 파일 오프셋, 메모리 이미지 읽기
    src/core/PeDirectories.cpp   # Import / Export
    src/core/PeRelocs.cpp        # Base Relocation
    src/core/PeFormat.h
    src/core/PeFormat.cpp        # 표시용 문자열 변환
)
target_include_directories(pecore PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

# core 검증용 CLI
add_executable(pedump tools/pedump.cpp)
target_link_libraries(pedump PRIVATE pecore)

# ---------------------------------------------------------------------------
# GUI: Qt6 Widgets
# ---------------------------------------------------------------------------
# Qt 위치: -DCMAKE_PREFIX_PATH 로 직접 주거나, 환경변수 QT_ROOT (기본 C:/Qt) 아래 버전 폴더를 찾는다.
# setup.ps1 이 같은 규칙으로 Qt를 설치한다.
set(PEPARSER_QT_VERSION "6.8.3" CACHE STRING "Qt version to look for under QT_ROOT")
set(PEPARSER_QT_ARCH "msvc2022_64" CACHE STRING "Qt arch folder under QT_ROOT/<version>")
if(DEFINED ENV{QT_ROOT})
    file(TO_CMAKE_PATH "$ENV{QT_ROOT}" _qt_root)
else()
    set(_qt_root "C:/Qt")
endif()
list(APPEND CMAKE_PREFIX_PATH "${_qt_root}/${PEPARSER_QT_VERSION}/${PEPARSER_QT_ARCH}")

find_package(Qt6 REQUIRED COMPONENTS Widgets)
qt_standard_project_setup()   # AUTOMOC / AUTOUIC 등

qt_add_executable(PEParser WIN32
    src/main.cpp
    src/gui/GuiCommon.h          # 페이지 파일 공통 헬퍼 (hex 포맷, 색, ADD_FIELD)
    src/gui/MainWindow.h
    src/gui/MainWindow.cpp       # 창 틀, 트리 뼈대, 테이블/Hex 공통, 이동
    src/gui/HeaderPages.cpp      # 헤더 노드/화면
    src/gui/SectionPages.cpp     # SECTION 노드/섹션 hex, 섹션 안 구조 배치
    src/gui/DirectoryPages.cpp   # Import / Export 화면
    src/gui/RelocPages.cpp       # Base Relocation 화면
    src/gui/HexView.h
    src/gui/HexView.cpp
)
target_link_libraries(PEParser PRIVATE pecore Qt6::Widgets)

# 빌드 후 Qt DLL을 실행 파일 옆에 배치 → 빌드 폴더에서 바로 실행 가능
if(WIN32)
    find_program(WINDEPLOYQT_EXE windeployqt HINTS "${Qt6_DIR}/../../../bin")
    if(WINDEPLOYQT_EXE)
        add_custom_command(TARGET PEParser POST_BUILD
            COMMAND "${WINDEPLOYQT_EXE}" --no-translations --no-compiler-runtime --no-system-d3d-compiler
                    --no-opengl-sw "$<TARGET_FILE:PEParser>"
            COMMENT "Deploying Qt runtime with windeployqt")
    endif()
endif()
