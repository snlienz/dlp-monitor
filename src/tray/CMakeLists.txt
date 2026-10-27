add_executable(DlpTray WIN32
  clipboard.cpp
  main.cpp
  pipe_client.cpp)
target_include_directories(DlpTray PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_link_libraries(DlpTray PRIVATE dlp_common comctl32 shell32 user32)
