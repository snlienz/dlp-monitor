FetchContent_Declare(googletest
  URL https://github.com/google/googletest/releases/download/v1.15.2/googletest-1.15.2.tar.gz
  DOWNLOAD_EXTRACT_TIMESTAMP ON)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_executable(dlp_tests
  bounded_queue_test.cpp
  detectors_test.cpp
  event_test.cpp
  pipe_protocol_test.cpp
  policy_engine_test.cpp)
target_link_libraries(dlp_tests PRIVATE dlp_agent_core GTest::gtest_main)

include(GoogleTest)
gtest_discover_tests(dlp_tests DISCOVERY_MODE PRE_TEST)
