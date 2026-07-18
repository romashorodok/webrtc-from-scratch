cmake_minimum_required(VERSION 3.25)
project(wrtc_pymeta_compiler_c VERSION 0.1 LANGUAGES C)

if(CMAKE_CROSSCOMPILING)
  message(FATAL_ERROR "wrtc-pymeta-compiler-c does not support cross-compiling")
endif()

find_package(Python3 REQUIRED COMPONENTS Interpreter Development.Embed Development.Module)

file(READ "${CMAKE_CURRENT_SOURCE_DIR}/kernel_e_extension.c.in" WRTC_TEMPLATE_HEX HEX)
string(REGEX REPLACE "(..)" "0x\\1," WRTC_TEMPLATE_BYTES "${WRTC_TEMPLATE_HEX}")
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/kernel_e_template.h"
  "static const unsigned char WRTC_EXTENSION_TEMPLATE[] = {${WRTC_TEMPLATE_BYTES}0x00};\n"
)

add_executable(wrtc-pymeta-compiler-c main.c)
target_compile_features(wrtc-pymeta-compiler-c PRIVATE c_std_17)
set_target_properties(wrtc-pymeta-compiler-c PROPERTIES
  C_STANDARD 17
  C_STANDARD_REQUIRED YES
  C_EXTENSIONS NO
)
target_link_libraries(wrtc-pymeta-compiler-c PRIVATE Python3::Python)
target_include_directories(wrtc-pymeta-compiler-c PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
target_compile_definitions(wrtc-pymeta-compiler-c PRIVATE
  WRTC_PYTHON_EXECUTABLE="${Python3_EXECUTABLE}"
  WRTC_PYTHON_VERSION="${Python3_VERSION}"
)

if(MSVC)
  target_compile_options(wrtc-pymeta-compiler-c PRIVATE /W4)
else()
  target_compile_options(wrtc-pymeta-compiler-c PRIVATE
    -Wall -Wextra -Wconversion -Werror
  )
endif()

install(TARGETS wrtc-pymeta-compiler-c RUNTIME DESTINATION bin)
