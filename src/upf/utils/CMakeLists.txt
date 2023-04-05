include_directories(${SRC_TOP_DIR}/../build/ext/spdlog/include)

add_library(upfutils
  Logger.cpp
  Util.cpp
  NextProgRuleKey.cpp
)

target_include_directories(upfutils PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}../>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../bpf>
)

# target_include_directories(upfutils PUBLIC
#   $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../include>
#   $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}../>
#   $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../bpf>
# )

install(
    TARGETS upfutils
    EXPORT "${TARGETS_EXPORT_NAME}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
    INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)

