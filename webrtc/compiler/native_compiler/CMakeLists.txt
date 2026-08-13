cmake_minimum_required(VERSION 3.25)
project(wrtc_pymeta_compiler_c VERSION 0.4 LANGUAGES C)

include(CTest)

if(CMAKE_CROSSCOMPILING)
  message(FATAL_ERROR "wrtc-pymeta-compiler-c does not support cross-compiling")
endif()

find_package(Python3 REQUIRED COMPONENTS Interpreter Development.Embed Development.Module)
find_package(Threads REQUIRED)

set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/aot_codegen.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/boxed_executor.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/native_storage.c")
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/boxed_executor.c"
  WRTC_BOXED_EXECUTOR_HEX HEX)
string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1,"
  WRTC_BOXED_EXECUTOR_BYTES "${WRTC_BOXED_EXECUTOR_HEX}")
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/boxed_executor_source.h"
  "static const unsigned char wrtc_boxed_executor_source[]={"
  "${WRTC_BOXED_EXECUTOR_BYTES}0};\n")
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/native_storage.c"
  WRTC_NATIVE_STORAGE_HEX HEX)
string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1,"
  WRTC_NATIVE_STORAGE_BYTES "${WRTC_NATIVE_STORAGE_HEX}")
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/native_storage_source.h"
  "static const unsigned char wrtc_native_storage_source[]={"
  "${WRTC_NATIVE_STORAGE_BYTES}0};\n")
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/native_reactor.h"
  WRTC_NATIVE_REACTOR_HEADER_HEX HEX)
string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1,"
  WRTC_NATIVE_REACTOR_HEADER_BYTES "${WRTC_NATIVE_REACTOR_HEADER_HEX}")
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/native_reactor.c"
  WRTC_NATIVE_REACTOR_IMPLEMENTATION_HEX HEX)
string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1,"
  WRTC_NATIVE_REACTOR_IMPLEMENTATION_BYTES
  "${WRTC_NATIVE_REACTOR_IMPLEMENTATION_HEX}")
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/native_reactor_source.h"
  "static const unsigned char wrtc_native_reactor_header_source[]={"
  "${WRTC_NATIVE_REACTOR_HEADER_BYTES}0};\n"
  "static const unsigned char wrtc_native_reactor_implementation_source[]={"
  "${WRTC_NATIVE_REACTOR_IMPLEMENTATION_BYTES}0};\n")
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/native_worker_source.h" "")
foreach(WRTC_WORKER_SOURCE native_worker_abi.h native_worker_record.h
    native_worker_record.c native_worker_executor.h native_worker_executor.c)
  string(REPLACE "." "_" WRTC_WORKER_SYMBOL "${WRTC_WORKER_SOURCE}")
  file(READ "${CMAKE_CURRENT_SOURCE_DIR}/${WRTC_WORKER_SOURCE}"
    WRTC_WORKER_HEX HEX)
  string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1,"
    WRTC_WORKER_BYTES "${WRTC_WORKER_HEX}")
  file(APPEND "${CMAKE_CURRENT_BINARY_DIR}/native_worker_source.h"
    "static const unsigned char ${WRTC_WORKER_SYMBOL}_source[]={"
    "${WRTC_WORKER_BYTES}0};\n")
endforeach()

add_library(wrtc-compiler-core STATIC aot_codegen.c boxed_codegen.c boxed_executor.c
  boxed_module.c compiler_core.c lowering.c native_runtime.c generator.c
  native_class.c native_class_generator.c native_operation.c native_storage.c
  native_storage_codegen.c native_worker_record.c native_worker_executor.c native_kernel.c
  native_reactor.c native_reactor_codegen.c native_worker_codegen.c
  statement_ir.c)
target_compile_features(wrtc-compiler-core PUBLIC c_std_17)
set_target_properties(wrtc-compiler-core PROPERTIES
  C_STANDARD 17 C_STANDARD_REQUIRED YES C_EXTENSIONS NO
)
target_link_libraries(wrtc-compiler-core PUBLIC Python3::Python)
target_include_directories(wrtc-compiler-core PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}" "${CMAKE_CURRENT_BINARY_DIR}")

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

  add_executable(native_class_c_test tests/native_class_c_test.c)
  target_link_libraries(native_class_c_test PRIVATE wrtc-compiler-core)
  add_test(NAME native_class_c_test COMMAND native_class_c_test)

  add_executable(statement_ir_c_test tests/statement_ir_c_test.c)
  target_link_libraries(statement_ir_c_test PRIVATE wrtc-compiler-core)
  add_test(NAME statement_ir_c_test COMMAND statement_ir_c_test)

  add_executable(boxed_executor_c_test tests/boxed_executor_c_test.c)
  target_link_libraries(boxed_executor_c_test PRIVATE wrtc-compiler-core)
  add_test(NAME boxed_executor_c_test COMMAND boxed_executor_c_test)

  add_executable(boxed_codegen_c_test tests/boxed_codegen_c_test.c)
  target_link_libraries(boxed_codegen_c_test PRIVATE wrtc-compiler-core)
  get_filename_component(WRTC_BOXED_PACKAGE_SOURCE
    "${CMAKE_CURRENT_SOURCE_DIR}/../../event_loop/scheduler.py" ABSOLUTE)
  target_compile_definitions(boxed_codegen_c_test PRIVATE
    WRTC_BOXED_PACKAGE_SOURCE="${WRTC_BOXED_PACKAGE_SOURCE}"
  )
  add_test(NAME boxed_codegen_c_test COMMAND boxed_codegen_c_test)

  add_executable(native_storage_c_test tests/native_storage_c_test.c)
  target_link_libraries(native_storage_c_test PRIVATE wrtc-compiler-core)
  add_test(NAME native_storage_c_test COMMAND native_storage_c_test)

  add_executable(native_storage_codegen_c_test
    tests/native_storage_codegen_c_test.c)
  target_link_libraries(native_storage_codegen_c_test PRIVATE
    wrtc-compiler-core)
  add_test(NAME native_storage_codegen_c_test
    COMMAND native_storage_codegen_c_test)

  add_executable(native_atomic_c_test tests/native_atomic_c_test.c)
  target_link_libraries(native_atomic_c_test PRIVATE
    wrtc-compiler-core Threads::Threads)
  add_test(NAME native_atomic_c_test COMMAND native_atomic_c_test)

  add_executable(native_mpsc_c_test tests/native_mpsc_c_test.c)
  target_link_libraries(native_mpsc_c_test PRIVATE
    wrtc-compiler-core Threads::Threads)
  add_test(NAME native_mpsc_c_test COMMAND native_mpsc_c_test)

  add_executable(native_spsc_c_test tests/native_spsc_c_test.c)
  target_link_libraries(native_spsc_c_test PRIVATE
    wrtc-compiler-core Threads::Threads)
  add_test(NAME native_spsc_c_test COMMAND native_spsc_c_test)

  add_executable(native_worker_record_c_test
    tests/native_worker_record_c_test.c)
  target_link_libraries(native_worker_record_c_test PRIVATE
    wrtc-compiler-core Threads::Threads)
  add_test(NAME native_worker_record_c_test
    COMMAND native_worker_record_c_test)

  add_executable(native_kernel_c_test tests/native_kernel_c_test.c)
  target_link_libraries(native_kernel_c_test PRIVATE wrtc-compiler-core)
  target_compile_definitions(native_kernel_c_test PRIVATE
    WRTC_NATIVE_COMPILER_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}")
  add_test(NAME native_kernel_c_test COMMAND native_kernel_c_test)

  add_executable(native_worker_executor_c_test
    tests/native_worker_executor_c_test.c)
  target_link_libraries(native_worker_executor_c_test PRIVATE
    wrtc-compiler-core)
  add_test(NAME native_worker_executor_c_test
    COMMAND native_worker_executor_c_test)

  add_executable(native_reactor_c_test tests/native_reactor_c_test.c)
  target_link_libraries(native_reactor_c_test PRIVATE wrtc-compiler-core)
  add_test(NAME native_reactor_c_test COMMAND native_reactor_c_test)
  add_custom_target(native_worker_executor_release_soak
    COMMAND ${CMAKE_COMMAND} -E env
      WRTC_WORKER_EXECUTOR_STRESS_COUNT=100000
      $<TARGET_FILE:native_worker_executor_c_test>
    DEPENDS native_worker_executor_c_test
    COMMENT "Running the 100000-item native worker executor Release soak"
    VERBATIM)

  add_executable(mpsc_proof_c_test tests/mpsc_proof_c_test.c)
  target_link_libraries(mpsc_proof_c_test PRIVATE wrtc-compiler-core)
  get_filename_component(WRTC_MPSC_PROOF_SOURCE
    "${CMAKE_CURRENT_SOURCE_DIR}/../../event_loop/mpsc_proof_fixture.py"
    ABSOLUTE)
  target_compile_definitions(mpsc_proof_c_test PRIVATE
    WRTC_MPSC_PROOF_SOURCE="${WRTC_MPSC_PROOF_SOURCE}"
  )
  add_test(NAME mpsc_proof_c_test COMMAND mpsc_proof_c_test)

  add_executable(native_operation_c_test tests/native_operation_c_test.c)
  target_link_libraries(native_operation_c_test PRIVATE wrtc-compiler-core)
  get_filename_component(WRTC_LOOP_SOURCE
    "${CMAKE_CURRENT_SOURCE_DIR}/../../event_loop/loop.py" ABSOLUTE)
  get_filename_component(WRTC_SCHEDULER_SOURCE
    "${CMAKE_CURRENT_SOURCE_DIR}/../../event_loop/scheduler.py" ABSOLUTE)
  target_compile_definitions(native_operation_c_test PRIVATE
    WRTC_LOOP_SOURCE="${WRTC_LOOP_SOURCE}"
    WRTC_SCHEDULER_SOURCE="${WRTC_SCHEDULER_SOURCE}"
  )
  add_test(NAME native_operation_c_test COMMAND native_operation_c_test)

  add_executable(capability_report_c_test tests/capability_report_c_test.c)
  target_link_libraries(capability_report_c_test PRIVATE wrtc-compiler-core)
  get_filename_component(WRTC_CAPABILITY_SOURCE
    "${CMAKE_CURRENT_SOURCE_DIR}/../../event_loop/capability_fixture.py"
    ABSOLUTE)
  target_compile_definitions(capability_report_c_test PRIVATE
    WRTC_CAPABILITY_SOURCE="${WRTC_CAPABILITY_SOURCE}"
  )
  add_test(NAME capability_report_c_test COMMAND capability_report_c_test)

  foreach(test_target frontend_c_test ir_c_test runtime_c_test lowering_c_test generator_c_test native_class_c_test statement_ir_c_test boxed_executor_c_test boxed_codegen_c_test native_storage_c_test native_storage_codegen_c_test native_atomic_c_test native_mpsc_c_test native_spsc_c_test native_worker_record_c_test native_worker_executor_c_test native_reactor_c_test native_kernel_c_test mpsc_proof_c_test native_operation_c_test capability_report_c_test)
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
