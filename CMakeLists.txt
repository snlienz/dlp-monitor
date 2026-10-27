cmake_minimum_required(VERSION 3.25)
project(DlpMonitor VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(DLP_BUILD_TESTS "Build unit tests" ON)
option(DLP_ANALYZE "Enable MSVC /analyze" OFF)

include(FetchContent)
FetchContent_Declare(json
  URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
  DOWNLOAD_EXTRACT_TIMESTAMP ON)
FetchContent_MakeAvailable(json)

add_library(dlp_warnings INTERFACE)
target_compile_options(dlp_warnings INTERFACE /W4 /WX /permissive- /utf-8 /EHsc)
target_compile_definitions(dlp_warnings INTERFACE
  UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00)
if(DLP_ANALYZE)
  target_compile_options(dlp_warnings INTERFACE /analyze /analyze:external-)
endif()

add_subdirectory(src/common)
add_subdirectory(src/agent)

if(DLP_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
