include_directories(.)

IF(DEBUG)
  add_definitions(-DDEBUG)
  #SET(CMAKE_BUILD_TYPE "Debug")
  #SET(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g -ggdb")
ENDIF()


add_library(
  csnark
  STATIC

  gadget2.cpp
  goLayer.cpp
)

target_link_libraries(
  csnark

  snark
)

target_include_directories(
  csnark

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)


add_executable(
  test-gadget

  test/test-gadget.cpp
)

add_executable(
  test-vcc

  test/test-vcc.cpp
  test/vcc.cpp
)

add_executable(
  keypairGen

  keyGen/keypairGen.cpp
)

target_link_libraries(
  test-gadget

  csnark
  gtest
)

target_link_libraries(
  test-vcc

  csnark
  gtest
)

target_link_libraries(
  keypairGen

  csnark
)

target_include_directories(
  test-gadget

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/gtest/googletest/include
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)

target_include_directories(
  test-vcc

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/gtest/googletest/include
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)

