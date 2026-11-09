# PE Parser

C++20 + Qt 6 Widgets 기반 Windows PE(Portable Executable) 파일 분석기.

## 빠른 시작 (새 PC)

```powershell
git clone <repo-url> Parser
cd Parser
.\setup.cmd -Build
.\build\Debug\PEParser.exe
```

`setup.cmd`는 없는 것만 설치하고, 여러 번 실행해도 안전합니다.

| 단계 | 내용 | 없을 때 |
|---|---|---|
| MSVC | Visual Studio 2022/2026 C++ 도구 | `winget`으로 VS 2022 Build Tools (C++ 워크로드) 설치 |
| CMake 3.21+ | PATH 또는 VS 내장 CMake | `winget install Kitware.CMake` |
| Python 3 | Qt 설치 도구 실행용 | `winget install Python.Python.3.13` |
| Qt 6.8.3 (LTS) | `msvc2022_64`, [aqtinstall](https://github.com/miurahr/aqtinstall)로 설치 (Qt 계정 불필요) | `C:\Qt`에 설치 |

옵션:

```powershell
.\setup.cmd                      # 환경만 설치
.\setup.cmd -Build -Config release
.\setup.cmd -QtRoot D:\Qt        # Qt를 다른 위치에 설치 → 사용자 환경변수 QT_ROOT 자동 등록
```

> 요구 사항: Windows 10/11 x64, `winget`(앱 설치 관리자), 인터넷 연결.
> VS Build Tools를 설치할 때는 UAC 창이 뜰 수 있습니다.

## 수동 빌드

```powershell
cmake --preset msvc              # 설치된 최신 Visual Studio 생성기를 자동으로 선택
cmake --build --preset debug     # 또는 release
```

CMake는 Qt를 `QT_ROOT`(기본값 `C:/Qt`)`/6.8.3/msvc2022_64`에서 찾습니다.
다른 Qt를 쓰려면 `-DCMAKE_PREFIX_PATH=<qt경로>`를 지정하세요.
빌드가 끝나면 `windeployqt`가 Qt DLL을 실행 파일 옆에 복사합니다.

## 구조

```
src/core/      Qt 비의존 PE 파싱 라이브러리 (pecore)
  PeTypes.h    DOS / File / Optional(PE32·PE32+) / Section 헤더 구조체
  PeFile.*     로드·파싱(경계 검사), RVA→파일 오프셋 변환, 표시용 헬퍼
src/gui/       Qt Widgets GUI (구조 트리 + 필드 테이블, 드래그 앤 드롭)
tools/pedump   core 검증용 콘솔 도구:  build\Debug\pedump.exe <file>
setup.ps1      개발 환경 설치 스크립트 (setup.cmd로 실행)
```

## 로드맵

- [x] DOS / NT / File / Optional 헤더, Data Directory, Section Table
- [ ] Import / Export Table
- [ ] Base Relocation, TLS, Debug, Resource
- [ ] Hex 뷰 + 선택 필드 하이라이트
