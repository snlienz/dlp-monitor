# Agent logic without the process entry point, linked by DlpAgent.exe and the unit tests.
add_library(dlp_agent_core STATIC
  agent.cpp
  config.cpp
  content_scanner.cpp
  detectors.cpp
  etw_parser.cpp
  etw_session.cpp
  file_tracker.cpp
  network_tracker.cpp
  pipe_server.cpp
  policy_engine.cpp
  process_tracker.cpp
  service.cpp
  volume_map.cpp)
target_include_directories(dlp_agent_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_link_libraries(dlp_agent_core PUBLIC dlp_common tdh advapi32 ws2_32 shell32 ole32)

add_executable(DlpAgent main.cpp)
target_link_libraries(DlpAgent PRIVATE dlp_agent_core)
# Ship the bundled policy next to the exe as the last-resort fallback.
add_custom_command(TARGET DlpAgent POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
    ${PROJECT_SOURCE_DIR}/policy/default_policy.json $<TARGET_FILE_DIR:DlpAgent>/default_policy.json)
