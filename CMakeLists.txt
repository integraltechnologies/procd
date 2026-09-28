cmake_minimum_required(VERSION 3.16)
project(procd C)

# The contract lives in a language-neutral C ABI; no language is privileged.
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Debug)
endif()

if(MSVC)
  add_compile_options(/W4 /D_CRT_SECURE_NO_WARNINGS)
else()
  add_compile_options(-Wall -Wextra -Wshadow)
endif()

# All backend TUs are guarded by platform macros, so compiling the full set is
# safe: exactly one defines procd_active_backend() for the target OS.
set(PROCD_SOURCES
  src/procd.c
  src/backend_linux.c
  src/backend_macos.c
  src/backend_windows.c)

# Per-domain lock serializes operations on a handle (see src/backend.h).
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

# -------- production library --------
add_library(procd STATIC ${PROCD_SOURCES})
target_include_directories(procd PUBLIC include)
target_link_libraries(procd PUBLIC Threads::Threads)

# -------- CLI --------
add_executable(procd-cli cli/main.c tests/qualify.c tests/witness.c)
target_link_libraries(procd-cli PRIVATE procd)
target_include_directories(procd-cli PRIVATE include tests)
set_target_properties(procd-cli PROPERTIES OUTPUT_NAME procd)

# -------- adversarial fixture --------
add_executable(procd-adversary tests/adversary.c tests/witness.c)
target_include_directories(procd-adversary PRIVATE tests)

# -------- tests --------
enable_testing()

add_executable(procd-unit-test tests/unit_test.c)
target_link_libraries(procd-unit-test PRIVATE procd)
target_include_directories(procd-unit-test PRIVATE include)
add_test(NAME unit COMMAND procd-unit-test)

add_executable(procd-qualify-test tests/qualify_test.c tests/qualify.c tests/witness.c)
target_link_libraries(procd-qualify-test PRIVATE procd)
target_include_directories(procd-qualify-test PRIVATE include tests)
add_test(NAME qualify COMMAND procd-qualify-test $<TARGET_FILE:procd-adversary>)
set_tests_properties(qualify PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 180)

add_executable(procd-recovery-test tests/recovery_test.c)
target_link_libraries(procd-recovery-test PRIVATE procd)
target_include_directories(procd-recovery-test PRIVATE include)
add_test(NAME recovery COMMAND procd-recovery-test)
set_tests_properties(recovery PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 120)

# Spawn-vs-terminate concurrency on one handle (Linux)
add_executable(procd-race-test tests/race_test.c)
target_link_libraries(procd-race-test PRIVATE procd)
target_include_directories(procd-race-test PRIVATE include)
add_test(NAME race COMMAND procd-race-test $<TARGET_FILE:procd-adversary>)
set_tests_properties(race PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 180)

# Workload identity: caller's credentials by default, optional explicit run-as (Linux)
add_executable(procd-identity-test tests/identity_test.c)
target_link_libraries(procd-identity-test PRIVATE procd)
target_include_directories(procd-identity-test PRIVATE include)
add_test(NAME identity COMMAND procd-identity-test $<TARGET_FILE:procd-adversary>)
set_tests_properties(identity PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 120)

# Descriptor hygiene: a caller descriptor does not leak into the task (Linux)
add_executable(procd-fd-inherit-test tests/fd_inherit_test.c tests/witness.c)
target_link_libraries(procd-fd-inherit-test PRIVATE procd)
target_include_directories(procd-fd-inherit-test PRIVATE include tests)
add_test(NAME fd_inherit COMMAND procd-fd-inherit-test $<TARGET_FILE:procd-adversary>)
set_tests_properties(fd_inherit PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 120)

# Establishment: ENFORCED follows the actual cgroup-v2 domain, incl. an unprivileged
# delegated caller; unusable environments are refused; downgrades report honestly (Linux)
add_executable(procd-establish-test tests/establish_test.c)
target_link_libraries(procd-establish-test PRIVATE procd)
target_include_directories(procd-establish-test PRIVATE include)
add_test(NAME establish COMMAND procd-establish-test)
set_tests_properties(establish PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 120)

# Failed-spawn isolation: a failed spawn never kills running workloads (Linux)
add_executable(procd-spawn-fail-test tests/spawn_fail_test.c tests/witness.c)
target_link_libraries(procd-spawn-fail-test PRIVATE procd)
target_include_directories(procd-spawn-fail-test PRIVATE include tests)
add_test(NAME spawn_fail COMMAND procd-spawn-fail-test $<TARGET_FILE:procd-adversary>)
set_tests_properties(spawn_fail PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 120)

# Real Cargo workload: procd domain -> shell -> cargo -> rustc / build script /
# test binary -> descendants, terminated mid-flight (all platforms; needs cargo)
add_executable(procd-cargo-test tests/cargo_test.c tests/witness.c)
target_link_libraries(procd-cargo-test PRIVATE procd)
target_include_directories(procd-cargo-test PRIVATE include tests)
add_test(NAME cargo_lifecycle
         COMMAND procd-cargo-test ${CMAKE_CURRENT_SOURCE_DIR}/tests/cargo_fixture/Cargo.toml
                 ${CMAKE_CURRENT_BINARY_DIR})
set_tests_properties(cargo_lifecycle PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 1200)

# TEST-ONLY negative-control library variant: production supervision can never
# be weakened; only this variant compiles the weakening switch.
add_library(procd_nc STATIC ${PROCD_SOURCES} src/negative_control.c)
target_include_directories(procd_nc PUBLIC include)
target_link_libraries(procd_nc PUBLIC Threads::Threads)
target_compile_definitions(procd_nc PUBLIC PROCD_ENABLE_NEGATIVE_CONTROL)

if(APPLE)
  # Tracked-domain regressions: caller-reaped leader, unrelated same-group
  # sibling, honest scan-based reporting.
  add_executable(procd-macos-tracking-test tests/macos_tracking_test.c tests/witness.c)
  target_link_libraries(procd-macos-tracking-test PRIVATE procd)
  target_include_directories(procd-macos-tracking-test PRIVATE include tests)
  add_test(NAME macos_tracking
           COMMAND procd-macos-tracking-test $<TARGET_FILE:procd-adversary>)
  set_tests_properties(macos_tracking PROPERTIES TIMEOUT 120)
endif()

if(WIN32)
  # Required Windows mechanism properties fail on missing witnesses. Known
  # escape investigations print INCONCLUSIVE without being relabeled PASS.
  add_executable(procd-windows-qualification-test tests/windows_qualification_test.c)
  target_link_libraries(procd-windows-qualification-test PRIVATE procd)
  target_include_directories(procd-windows-qualification-test PRIVATE include)
  add_test(NAME windows_qualification
           COMMAND procd-windows-qualification-test $<TARGET_FILE:procd-adversary>)
  set_tests_properties(windows_qualification PROPERTIES TIMEOUT 150)
endif()

# Cargo harness against weakened supervision (PROCD_NC_WEAKEN=1): must FAIL,
# proving the Cargo oracle sees leaked cargo/build-script/test descendants.
add_executable(procd-cargo-test-nc tests/cargo_test.c tests/witness.c)
target_link_libraries(procd-cargo-test-nc PRIVATE procd_nc)
target_include_directories(procd-cargo-test-nc PRIVATE include tests)

add_executable(procd-negative-control-test tests/negative_control_test.c tests/witness.c)
target_link_libraries(procd-negative-control-test PRIVATE procd_nc)
target_include_directories(procd-negative-control-test PRIVATE include tests)
if(WIN32)
  # The production comparison is a separate process linked to the production
  # library. It cannot inherit the test-only weakening implementation/state.
  add_executable(procd-negative-control-production-test
                 tests/negative_control_test.c tests/witness.c)
  target_link_libraries(procd-negative-control-production-test PRIVATE procd)
  target_include_directories(procd-negative-control-production-test PRIVATE include tests)
  target_compile_definitions(procd-negative-control-production-test
                             PRIVATE PROCD_NC_PRODUCTION_HELPER)
  add_test(NAME negative_control
           COMMAND procd-negative-control-test
                   $<TARGET_FILE:procd-adversary>
                   $<TARGET_FILE:procd-negative-control-production-test>)
else()
  add_test(NAME negative_control
           COMMAND procd-negative-control-test $<TARGET_FILE:procd-adversary>)
endif()
set_tests_properties(negative_control PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 180)
