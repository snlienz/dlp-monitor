add_library(dlp_common STATIC
  event.cpp
  log.cpp
  pipe_protocol.cpp
  wstr.cpp)
target_include_directories(dlp_common PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_link_libraries(dlp_common PUBLIC dlp_warnings nlohmann_json::nlohmann_json)
