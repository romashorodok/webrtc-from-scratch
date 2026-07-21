cmake_minimum_required(VERSION 3.25)
project(wrtc_pymeta_compiler_c VERSION 0.3 LANGUAGES C)

include(CTest)

if(CMAKE_CROSSCOMPILING)
  message(FATAL_ERROR "wrtc-pymeta-compiler-c does not support cross-compiling")
endif()

find_package(Python3 REQUIRED COMPONENTS Interpreter Development.Embed Development.Module)

add_library(wrtc-compiler-core STATIC compiler_core.c lowering.c native_runtime.c generator.c)
target_compile_features(wrtc-compiler-core PUBLIC c_std_17)
set_target_properties(wrtc-compiler-core PROPERTIES
  C_STANDARD 17 C_STANDARD_REQUIRED YES C_EXTENSIONS NO
)
target_link_libraries(wrtc-compiler-core PUBLIC Python3::Python)
target_include_directories(wrtc-compiler-core PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")

add_executable(wrtc-pymeta-compiler-c main.c)
target_compile_features(wrtc-pymeta-compiler-c PRIVATE c_std_17)
set_target_properties(wrtc-pymeta-compiler-c PROPERTIES
  C_STANDARD 17
  C_STANDARD_REQUIRED YES
  C_EXTENSIONS NO
)
target_link_libraries(wrtc-pymeta-compiler-c PRIVATE wrtc-compiler-core Python3::Python)
target_include_directories(wrtc-pymeta-compiler-c PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_compile_definitions(wrtc-pymeta-compiler-c PRIVATE
  WRTC_PYTHON_EXECUTABLE="${Python3_EXECUTABLE}"
  WRTC_PYTHON_VERSION="${Python3_VERSION}"
)

if(MSVC)
  target_compile_options(wrtc-compiler-core PRIVATE /W4)
  target_compile_options(wrtc-pymeta-compiler-c PRIVATE /W4)
else()
  target_compile_options(wrtc-compiler-core PRIVATE
    -Wall -Wextra -Wconversion -Werror
  )
  target_compile_options(wrtc-pymeta-compiler-c PRIVATE
    -Wall -Wextra -Wconversion -Werror
  )
endif()

install(TARGETS wrtc-pymeta-compiler-c RUNTIME DESTINATION bin)

if(BUILD_TESTING)
  add_executable(frontend_c_test tests/frontend_c_test.c)
  target_link_libraries(frontend_c_test PRIVATE wrtc-compiler-core)
  add_test(NAME frontend_c_test COMMAND frontend_c_test)

  add_executable(ir_c_test tests/ir_c_test.c)
  target_link_libraries(ir_c_test PRIVATE wrtc-compiler-core)
  target_compile_definitions(ir_c_test PRIVATE
    WRTC_KERNEL_E_SOURCE="${CMAKE_CURRENT_SOURCE_DIR}/../kernel_e.py"
  )
  add_test(NAME ir_c_test COMMAND ir_c_test)

  add_executable(runtime_c_test tests/runtime_c_test.c)
  target_link_libraries(runtime_c_test PRIVATE wrtc-compiler-core)
  add_test(NAME runtime_c_test COMMAND runtime_c_test)

  add_executable(lowering_c_test tests/lowering_c_test.c)
  target_link_libraries(lowering_c_test PRIVATE wrtc-compiler-core)
  target_compile_definitions(lowering_c_test PRIVATE
    WRTC_KERNEL_E_SOURCE="${CMAKE_CURRENT_SOURCE_DIR}/../kernel_e.py"
  )
  add_test(NAME lowering_c_test COMMAND lowering_c_test)

  add_executable(generator_c_test tests/generator_c_test.c)
  target_link_libraries(generator_c_test PRIVATE wrtc-compiler-core)
  add_test(NAME generator_c_test COMMAND generator_c_test)

  foreach(test_target frontend_c_test ir_c_test runtime_c_test lowering_c_test generator_c_test)
    set_target_properties(${test_target} PROPERTIES
      C_STANDARD 17 C_STANDARD_REQUIRED YES C_EXTENSIONS NO
    )
    if(MSVC)
      target_compile_options(${test_target} PRIVATE /W4)
    else()
      target_compile_options(${test_target} PRIVATE
        -Wall -Wextra -Wconversion -Werror
      )
    endif()
  endforeach()
endif()
