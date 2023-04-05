set(CMAKE_C_FLAGS "-Wno-unused-but-set-variable -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function -Wno-error -Wno-return-type")

include_directories(${SRC_TOP_DIR}/upf/include)
include_directories(${SRC_TOP_DIR}/upf)
include_directories(${SRC_TOP_DIR}/upf/bpf)

add_definitions(-DKERNEL_SPACE)

add_custom_target(upf_xdp_bpf_all DEPENDS upf_xdp_bpf session_bpf far_bpf)

function(bpf prefix)
  add_library(${prefix}_bpf ${prefix}_bpf.c)
  add_custom_command(
    TARGET ${prefix}_bpf
    PRE_LINK
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_SOURCE_DIR}/../skel
    COMMAND bpftool gen skeleton $<TARGET_OBJECTS:${prefix}_bpf> > ${CMAKE_CURRENT_SOURCE_DIR}/../skel/${prefix}_bpf_skel.h
    COMMAND sed -i '9i\#define typeof\(x\) __typeof__\(x\)' ${CMAKE_CURRENT_SOURCE_DIR}/../skel/${prefix}_bpf_skel.h
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${prefix}_bpf.c
  )
endfunction()

bpf(upf_xdp)
bpf(session)
bpf(far)
