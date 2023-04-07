# include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/toolchain.cmake)
add_subdirectory(bpf)
add_subdirectory(oai)
add_subdirectory(utils)
include_directories(${SRC_TOP_DIR}/upf/bpf)
include_directories(${SRC_TOP_DIR}/upf/bpf/pfcp)
include_directories(${SRC_TOP_DIR}/common)
include_directories(${SRC_TOP_DIR}/common/msg)
include_directories(${SRC_TOP_DIR}/common/utils)
include_directories(${SRC_TOP_DIR}/../build/ext/spdlog/include)

set(GTP_INTERFACE $ENV{GTP_INTERFACE})
set(UDP_INTERFACE $ENV{UDP_INTERFACE})
set(SOCKET_BUFFER_ENABLED $ENV{SOCKET_BUFFER_ENABLED})

add_library(UPF_XDP STATIC
  UserPlaneComponent.cpp
  Configuration.cpp
  SignalHandler.cpp
  # SessionProgramManager.cpp
  # SessionManager.cpp
  SessionPrograms.cpp
  programs/UPFProgram.cpp
  programs/SessionProgram.cpp
  programs/FARProgram.cpp
  programs/BPFProgram.cpp
  wrappers/BPFMaps.cpp
  wrappers/BPFMap.cpp
  # utils/Logger.cpp
  # utils/Util.cpp
  # utils/NextProgRuleKey.cpp
)

link_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../build/ext/libbpf/src)
target_link_libraries(UPF_XDP
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../build/ext/libbpf/src/libbpf.a
  ${CMAKE_CURRENT_SOURCE_DIR}/../../build/ext/libbpf/src/libbpf.so
  PUBLIC oai
  PUBLIC upfutils
  # PRIVATE spdlog::spdlog
  PRIVATE elf
  PRIVATE z
)

target_include_directories(UPF_XDP PUBLIC
  $<BUILD_INTERFACE:${SRC_TOP_DIR}/upf/include>
  $<BUILD_INTERFACE:${SRC_TOP_DIR}/upf/>
  $<BUILD_INTERFACE:${SRC_TOP_DIR}/upf/bpf>
  $<BUILD_INTERFACE:${SRC_TOP_DIR}/upf/skel>
  $<BUILD_INTERFACE:${SRC_TOP_DIR}/upf/interfaces>
  # $<BUILD_INTERFACE:${SRC_TOP_DIR}/upf/observer>
  $<BUILD_INTERFACE:${SRC_TOP_DIR}/upf/programs>
)

add_dependencies(UPF_XDP upf_xdp_bpf_all)

# configure_file (
#     ${PROJECT_SOURCE_DIR}/cmake/Configuration.h.in
#     ${PROJECT_SOURCE_DIR}/src/Configuration.h
# )

# configure_file (
#     ${PROJECT_SOURCE_DIR}/cmake/Configuration.cpp.in
#     ${PROJECT_SOURCE_DIR}/src/Configuration.cpp
# )

# Targets:
#   * <prefix>/lib/upf_bpf.a
#   * header location after install: <prefix>/include/*.h
#   * headers can be included by C++ code `#include <*/*.h>`
install(
    TARGETS UPF_XDP
    EXPORT "${TARGETS_EXPORT_NAME}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
    INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)

# Headers:
#   * ./*.h -> <prefix>/include/*.h
# install(
#     DIRECTORY "./"
#     DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
#     FILES_MATCHING PATTERN "*.h"
# )
