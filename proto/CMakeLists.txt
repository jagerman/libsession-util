
function(check_target target)
    if (NOT TARGET ${target})
        message(FATAL_ERROR "Project failed to compile required target: ${target}")
    endif()
endfunction()

include(FetchContent)

FetchContent_Declare(
    protobuf
    GIT_REPOSITORY  https://github.com/protocolbuffers/protobuf.git
    GIT_TAG         v4.24.2     # apparently this must be a tag (not hash) for git_shallow to work?
    GIT_SHALLOW     TRUE
    GIT_PROGRESS    TRUE
)

set(protobuf_VERBOSE ON CACHE BOOL "" FORCE)
set(protobuf_INSTALL OFF CACHE BOOL "" FORCE)
set(protobuf_WITH_ZLIB OFF CACHE BOOL "" FORCE)
set(protobuf_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(protobuf_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(protobuf_BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(protobuf_ABSL_PROVIDER "module" CACHE STRING "" FORCE)
set(protobuf_BUILD_PROTOC_BINARIES ON CACHE BOOL "" FORCE)
set(protobuf_BUILD_PROTOBUF_BINARIES ON CACHE BOOL "" FORCE)

message(STATUS "Pulling protobuf repository...")

FetchContent_MakeAvailable(protobuf)

check_target(protobuf::libprotobuf-lite)
check_target(protobuf::libprotobuf)
check_target(protobuf::libprotoc)
check_target(protobuf::protoc)

set(Protobuf_INCLUDE_DIR "${protobuf_SOURCE_DIR}/src" CACHE INTERNAL "")
set(Protobuf_LIBRARIES protobuf::libprotobuf CACHE INTERNAL "")
find_package(Protobuf REQUIRED) # makes protobuf_generate_cpp available

include_directories(${CMAKE_CURRENT_BINARY_DIR})

add_library(protos protos.cpp)
target_link_libraries(protos PUBLIC ${Protobuf_LIBRARIES} libsession::config)

foreach(pfile SessionProtos WebSocketResources)
    protobuf_generate_cpp(${pfile}_PROTO_SRCS ${pfile}_PROTO_HDRS ${pfile}.proto)
    target_sources(protos PUBLIC ${${pfile}_PROTO_SRCS})
endforeach()

add_executable(test_proto test_proto.cpp)
target_link_libraries(test_proto PUBLIC protos)
