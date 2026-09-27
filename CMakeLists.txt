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

# B1/B3: privilege-identity + prerequisite honesty (Linux, needs enforced host)
add_executable(procd-enforce-prereq-test tests/enforce_prereq_test.c)
target_link_libraries(procd-enforce-prereq-test PRIVATE procd)
target_include_directories(procd-enforce-prereq-test PRIVATE include)
add_test(NAME enforce_prereq COMMAND procd-enforce-prereq-test)
set_tests_properties(enforce_prereq PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 120)

# B2: inherited-descriptor escape (Linux, needs enforced host)
add_executable(procd-fd-escape-test tests/fd_escape_test.c)
target_link_libraries(procd-fd-escape-test PRIVATE procd)
target_include_directories(procd-fd-escape-test PRIVATE include)
add_test(NAME fd_escape COMMAND procd-fd-escape-test $<TARGET_FILE:procd-adversary>)
set_tests_properties(fd_escape PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 120)

# Cleanup pass: spawn-vs-terminate concurrency (Linux, needs enforced host)
add_executable(procd-race-test tests/race_test.c)
target_link_libraries(procd-race-test PRIVATE procd)
target_include_directories(procd-race-test PRIVATE include)
add_test(NAME race COMMAND procd-race-test $<TARGET_FILE:procd-adversary>)
set_tests_properties(race PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 180)

# Cleanup pass: recovery preserves spawn security policy (Linux, needs enforced host)
add_executable(procd-recover-policy-test tests/recover_policy_test.c)
target_link_libraries(procd-recover-policy-test PRIVATE procd)
target_include_directories(procd-recover-policy-test PRIVATE include)
add_test(NAME recover_policy COMMAND procd-recover-policy-test)
set_tests_properties(recover_policy PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 120)

# Area 1: the workload runs with the intended FINAL credentials (Linux, enforced host)
add_executable(procd-identity-test tests/identity_test.c)
target_link_libraries(procd-identity-test PRIVATE procd)
target_include_directories(procd-identity-test PRIVATE include)
add_test(NAME identity COMMAND procd-identity-test $<TARGET_FILE:procd-adversary>)
set_tests_properties(identity PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 120)

# Area 2: an ordinary inherited writable descriptor is not usable by the workload
add_executable(procd-fd-inherit-test tests/fd_inherit_test.c)
target_link_libraries(procd-fd-inherit-test PRIVATE procd)
target_include_directories(procd-fd-inherit-test PRIVATE include)
add_test(NAME fd_inherit COMMAND procd-fd-inherit-test $<TARGET_FILE:procd-adversary>)
set_tests_properties(fd_inherit PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 120)

# Area 3: ENFORCED is established per invocation, not inferred; downgrade reports honestly
add_executable(procd-establish-test tests/establish_test.c)
target_link_libraries(procd-establish-test PRIVATE procd)
target_include_directories(procd-establish-test PRIVATE include)
add_test(NAME establish COMMAND procd-establish-test)
set_tests_properties(establish PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 120)

# TEST-ONLY negative-control library variant: production containment can never
# be weakened; only this variant compiles the weakening switch.
add_library(procd_nc STATIC ${PROCD_SOURCES} src/negative_control.c)
target_include_directories(procd_nc PUBLIC include)
target_link_libraries(procd_nc PUBLIC Threads::Threads)
target_compile_definitions(procd_nc PUBLIC PROCD_ENABLE_NEGATIVE_CONTROL)

# Area 1: a forced credential-transition failure fails the launch closed and runs
# no workload, without killing the domain's already-running workloads (Linux).
# Links the negative-control variant to force the failure deterministically.
add_executable(procd-cred-fail-test tests/cred_fail_test.c tests/witness.c)
target_link_libraries(procd-cred-fail-test PRIVATE procd_nc)
target_include_directories(procd-cred-fail-test PRIVATE include tests)
add_test(NAME cred_fail COMMAND procd-cred-fail-test $<TARGET_FILE:procd-adversary>)
set_tests_properties(cred_fail PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 120)

if(APPLE)
  add_executable(procd-macos-escape-test tests/macos_escape_test.c)
  target_link_libraries(procd-macos-escape-test PRIVATE procd)
  target_include_directories(procd-macos-escape-test PRIVATE include)
  add_test(NAME macos_escape
           COMMAND procd-macos-escape-test $<TARGET_FILE:procd-adversary>)
  set_tests_properties(macos_escape PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 120)

  add_executable(procd-macos-pgid-test tests/macos_pgid_test.c tests/witness.c)
  target_link_libraries(procd-macos-pgid-test PRIVATE procd)
  target_include_directories(procd-macos-pgid-test PRIVATE include tests)
  add_test(NAME macos_pgid_safety
           COMMAND procd-macos-pgid-test $<TARGET_FILE:procd-adversary>)
  set_tests_properties(macos_pgid_safety PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 120)
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
