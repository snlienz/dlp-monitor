# Platform-independent agent logic, linked by DlpAgent.exe and the unit tests.
add_library(dlp_agent_core STATIC
  detectors.cpp
  policy_engine.cpp)
target_include_directories(dlp_agent_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_link_libraries(dlp_agent_core PUBLIC dlp_common)
