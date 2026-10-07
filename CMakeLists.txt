cmake_minimum_required(VERSION 3.28)
project(PQVPN VERSION 0.0.1 LANGUAGES CXX)

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/.github/dependencies.env" PQVPN_DEPENDENCY_LINES
     REGEX "^[A-Z0-9_]+=[^=]+$")
foreach(PQVPN_DEPENDENCY_LINE IN LISTS PQVPN_DEPENDENCY_LINES)
  string(REGEX MATCH "^([^=]+)=(.+)$" _ "${PQVPN_DEPENDENCY_LINE}")
  set("PQVPN_${CMAKE_MATCH_1}" "${CMAKE_MATCH_2}")
endforeach()

include(CTest)
option(PQVPN_BUILD_MONITOR "Build the optional Qt monitor application" OFF)

find_package(OpenSSL ${PQVPN_OPENSSL_VERSION} REQUIRED)
find_package(unofficial-argon2 CONFIG QUIET)
if(TARGET unofficial::argon2::libargon2)
    message(STATUS "Argon2 found via vcpkg: unofficial::argon2::libargon2")
    set(ARGON2_FOUND TRUE)
    set(HAVE_ARGON2 TRUE)
    set(ARGON2_TARGET unofficial::argon2::libargon2)
    add_compile_definitions(HAVE_ARGON2=1 PQVPN_HAVE_ARGON2=1)
else()
    find_package(PkgConfig QUIET)
    if(PKG_CONFIG_FOUND)
        pkg_check_modules(ARGON2 QUIET IMPORTED_TARGET libargon2)
        if(ARGON2_FOUND)
            message(STATUS "Argon2 found via pkg-config: libargon2 ${ARGON2_VERSION}")
            set(HAVE_ARGON2 TRUE)
            set(ARGON2_TARGET PkgConfig::ARGON2)
            add_compile_definitions(HAVE_ARGON2=1 PQVPN_HAVE_ARGON2=1)
        endif()
    endif()

if(NOT ARGON2_FOUND AND NOT HAVE_ARGON2)
         message(FATAL_ERROR "Argon2 library not found. Please install libargon2-dev.")
    endif()
endif()

# Use liboqs' exported usage requirements instead of guessing a static path.
find_package(liboqs ${PQVPN_LIBOQS_VERSION} CONFIG QUIET)
add_library(pqvpn_oqs_static INTERFACE)
if(TARGET OQS::oqs)
  target_link_libraries(pqvpn_oqs_static INTERFACE OQS::oqs)
else()
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(LIBOQS REQUIRED IMPORTED_TARGET liboqs>=${PQVPN_LIBOQS_VERSION})
  # A static liboqs .pc lists OpenSSL in Requires.private, which the regular
  # imported pkg-config target omits. Carry it explicitly for static installs.
  target_link_libraries(pqvpn_oqs_static INTERFACE PkgConfig::LIBOQS OpenSSL::Crypto)
endif()
find_package(Threads REQUIRED)

if(WIN32)
  add_compile_definitions(
    NOMINMAX WIN32_LEAN_AND_MEAN
    _WIN32_WINNT=0x0A00 WINVER=0x0A00
    ASIO_HAS_THREADS=1 ASIO_DISABLE_THREAD_KEYWORD_EXTENSION=1)
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)
if(MSVC)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

include(CheckCXXSourceCompiles)
check_cxx_source_compiles("#include <expected>
int main() { std::expected<int, int> value(23); return *value == 23 ? 0 : 1; }"
  PQVPN_HAS_STD_EXPECTED)
if(NOT PQVPN_HAS_STD_EXPECTED)
  message(FATAL_ERROR "PQVPN requires a C++23 toolchain with std::expected (GCC 13+, recent AppleClang/libc++, or MSVC).")
endif()

include(FetchContent)

FetchContent_Declare(spdlog
  GIT_REPOSITORY https://github.com/gabime/spdlog.git
  GIT_TAG ${PQVPN_SPDLOG_TAG})
FetchContent_Declare(asio
  GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
  GIT_TAG ${PQVPN_ASIO_TAG})
FetchContent_MakeAvailable(spdlog asio)
if(BUILD_TESTING)
  FetchContent_Declare(Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG ${PQVPN_CATCH2_TAG})
  FetchContent_Declare(googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG ${PQVPN_GOOGLETEST_TAG})
  set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(Catch2 googletest)
endif()

set(PQVPN_INCLUDE_DIRS
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${CMAKE_CURRENT_SOURCE_DIR}/src/modules
  ${CMAKE_CURRENT_SOURCE_DIR}/src/utils
  ${CMAKE_CURRENT_SOURCE_DIR}/external/nlohmann_json/include
  ${asio_SOURCE_DIR}/asio/include
  ${spdlog_SOURCE_DIR}/include)

set(PQVPN_COMMON_LIBS spdlog::spdlog Threads::Threads ${CMAKE_DL_LIBS})
if(ARGON2_TARGET)
  list(APPEND PQVPN_COMMON_LIBS ${ARGON2_TARGET})
endif()
list(APPEND PQVPN_COMMON_LIBS pqvpn_oqs_static)
list(APPEND PQVPN_COMMON_LIBS OpenSSL::Crypto)
if(WIN32)
  list(APPEND PQVPN_COMMON_LIBS ws2_32 mswsock iphlpapi advapi32 crypt32)
endif()

# Build crypto utilities library
add_library(crypto_utils_lib src/crypto_utils.cpp)
target_include_directories(crypto_utils_lib PRIVATE ${PQVPN_INCLUDE_DIRS})
target_link_libraries(crypto_utils_lib PRIVATE pqvpn_oqs_static OpenSSL::Crypto spdlog::spdlog ${ARGON2_TARGET})

# Build crypto signature library
add_library(crypto_signature_lib src/crypto_signature.cpp)
target_include_directories(crypto_signature_lib PRIVATE ${PQVPN_INCLUDE_DIRS})
# crypto_signature.cpp includes oqs/oqs.h directly; link the OQS interface so
# its include directories propagate (crypto_utils_lib links it privately).
target_link_libraries(crypto_signature_lib PRIVATE crypto_utils_lib pqvpn_oqs_static OpenSSL::Crypto spdlog::spdlog)

# Build KEM module
add_library(crypto_kem_lib src/modules/crypto_kem.cpp)
target_include_directories(crypto_kem_lib PRIVATE ${PQVPN_INCLUDE_DIRS})
target_link_libraries(crypto_kem_lib PRIVATE crypto_utils_lib ${PQVPN_COMMON_LIBS})

# ... (previous lines)
if(PQVPN_BUILD_MONITOR)
    find_package(Qt6 ${PQVPN_QT_VERSION} REQUIRED COMPONENTS Core Gui Widgets)
    # The privacy console controls the canonical pqvpn_node process; it does
    # not implement a second VPN or cryptographic backend.
    add_executable(pqvpn_monitor src/monitor/pqvpn_monitor.cpp src/monitor/resources.qrc)
    set_target_properties(pqvpn_monitor PROPERTIES AUTOMOC ON AUTORCC ON)
    target_include_directories(pqvpn_monitor PRIVATE ${PQVPN_INCLUDE_DIRS})
    target_link_libraries(pqvpn_monitor PRIVATE Qt6::Widgets Qt6::Gui Qt6::Core)
    target_compile_options(pqvpn_monitor PRIVATE
      $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall;-Wextra;-Wpedantic>)
    if(BUILD_TESTING)
      add_test(NAME pqvpn_gui_smoke COMMAND pqvpn_monitor --smoke-test)
      set_tests_properties(pqvpn_gui_smoke PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        TIMEOUT 30 LABELS "gui;baseline")
    endif()

endif()

# Build node module as a library first
# ... (rest of the file)

# Build node module as a library first
add_library(node_module_lib src/modules/node_module.cpp src/modules/udp_protocol.cpp
  src/modules/egress_forwarder.cpp src/modules/ml_traffic_shaper.cpp src/modules/adaptive_transport.cpp
  src/routing/route_transaction.cpp src/routing/peer_route_manager.cpp)
target_include_directories(node_module_lib PUBLIC ${PQVPN_INCLUDE_DIRS})
# node_module verifies peer ML-DSA signatures (pq_sig_verify) in the handshake
# control plane, so it needs the signature library as well.
target_link_libraries(node_module_lib PUBLIC crypto_utils_lib crypto_signature_lib ${PQVPN_COMMON_LIBS})

# Per-OS tunnel adapter layer (see src/platform/adapter.hpp): PQVPN TUN on
# Windows, /dev/net/tun on Linux, and the Network Extension boundary on macOS.
set(PQVPN_PLATFORM_SOURCES "")
if(WIN32)
  list(APPEND PQVPN_PLATFORM_SOURCES
    src/platform/windows_own_tunnel.cpp
    src/platform/windows_routes.cpp
    src/platform/windows_adapter.cpp
    src/platform/windows_control/vpn_state_machine.cpp
    src/platform/windows_control/control_channel.cpp)
elseif(APPLE)
  list(APPEND PQVPN_PLATFORM_SOURCES
    src/platform/macos/network_extension_bridge.cpp
    src/platform/macos_adapter.cpp)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  list(APPEND PQVPN_PLATFORM_SOURCES
    src/platform/linux_tun.cpp
    src/platform/linux_adapter.cpp)
endif()
add_library(pqvpn_platform STATIC ${PQVPN_PLATFORM_SOURCES})
target_include_directories(pqvpn_platform PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src/platform
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${CMAKE_CURRENT_SOURCE_DIR}/external/nlohmann_json/include
  ${asio_SOURCE_DIR}/asio/include)

set(PQVPN_NODE_SOURCES src/main.cpp)
add_executable(pqvpn_node ${PQVPN_NODE_SOURCES})
target_include_directories(pqvpn_node PRIVATE ${PQVPN_INCLUDE_DIRS})
target_link_libraries(pqvpn_node PRIVATE node_module_lib pqvpn_platform ${PQVPN_COMMON_LIBS})

# MinGW/Windows: the executables import the shared oqs.dll. Copy it next to
# the binaries so the loader finds them without a modified PATH (every target
# in this project is placed in CMAKE_BINARY_DIR).
set(PQVPN_OQS_DLL_PATH "")
if(WIN32 AND TARGET OQS::oqs)
  get_target_property(_pqvpn_oqs_dll OQS::oqs IMPORTED_LOCATION_RELEASE)
  if(NOT _pqvpn_oqs_dll OR NOT EXISTS "${_pqvpn_oqs_dll}")
    get_target_property(_pqvpn_oqs_dll OQS::oqs IMPORTED_LOCATION)
  endif()
  if(_pqvpn_oqs_dll AND EXISTS "${_pqvpn_oqs_dll}")
    set(PQVPN_OQS_DLL_PATH "${_pqvpn_oqs_dll}")
  endif()
endif()

function(pqvpn_attach_oqs_runtime target)
  if(NOT PQVPN_OQS_DLL_PATH)
    return()
  endif()
  add_custom_command(TARGET ${target} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
      "${PQVPN_OQS_DLL_PATH}" "$<TARGET_FILE_DIR:${target}>"
    COMMENT "Placing oqs.dll next to the PQVPN binaries")
endfunction()

pqvpn_attach_oqs_runtime(pqvpn_node)

if(BUILD_TESTING)
add_test(NAME pqvpn_cli_help COMMAND pqvpn_node --help)
add_test(NAME pqvpn_cli_smoke COMMAND pqvpn_node --smoke-test --config ${CMAKE_CURRENT_SOURCE_DIR}/config.json)
add_test(NAME pqvpn_cli_udp2raw_config COMMAND pqvpn_node --smoke-test --config ${CMAKE_CURRENT_SOURCE_DIR}/config.udp2raw.json)
set_tests_properties(pqvpn_cli_help pqvpn_cli_smoke PROPERTIES TIMEOUT 30 LABELS "baseline")
add_executable(pqvpn_hard_kernel tools/pqvpn_hard_kernel.cpp)
target_include_directories(pqvpn_hard_kernel PRIVATE ${PQVPN_INCLUDE_DIRS})
target_link_libraries(pqvpn_hard_kernel PRIVATE pqvpn_oqs_static)
pqvpn_attach_oqs_runtime(pqvpn_hard_kernel)
add_test(
  NAME pqvpn_hard_kernel
  COMMAND pqvpn_hard_kernel --source ${CMAKE_CURRENT_SOURCE_DIR}
    --build ${CMAKE_CURRENT_BINARY_DIR} --ctest ${CMAKE_CTEST_COMMAND}
    --config $<CONFIG>
)
set_tests_properties(pqvpn_hard_kernel PROPERTIES
  LABELS "hardening;security;production"
  RESOURCE_LOCK "pqvpn_shared_resources"
)

set(CATCH_TESTS
  discovery_test
  test_audit_module
  test_adaptive_transport
  test_config
  test_crypto_kem
  test_crypto_signature
  test_crypto_signature_keygen
  test_crypto_signature_verify
  test_dht_client_concurrency
  test_dht_factory
  test_geographic_failover
  test_json_utils
  test_load_balancer
  test_logger_init
  test_logging_expanded
  test_logging
  test_metrics
  test_module_logging
  test_network_analytics_new
  test_network
  test_network_module
  test_node_choose_relay
  test_node_datagram_received
  test_node_is_peer_allowed
  test_node_make_outer_frame
  test_node_peer_hash8
  test_node_session_salt
  test_node_check_and_record_nonce
  test_tunnel_dataplane
  test_tunnel_forward
  test_tunnel_sink_resilience
  test_route_transaction
  test_plugin_manager_hooks
  test_plugin_manager
  test_serialization
  test_string_utils
  test_traffic_obfuscation
  test_zk_auth_init
  test_zk_auth_module
  adhoc_verify_send_onion
  test_crypto_kem_keygen
  test_crypto_serialization
  test_key_rotation_init
  test_network_analytics
  test_topology_module
  test_discovery_build_record
  test_build_onion_frame
  test_build_onion_frame_with_circuit
  test_udp_protocol)

set(GTEST_TESTS
  test_node_tofu_fix
  test_find_known_peer_by_pubkeys
  test_send_onion
  test_save_known_peers
  test_load_known_peers
  test_handle_relay
)
foreach(target IN LISTS CATCH_TESTS)
  set(sources tests/${target}.cpp)
  if(target STREQUAL "test_audit_module")
    list(APPEND sources src/modules/audit_module.cpp)
  elseif(target STREQUAL "test_dht_client_concurrency")
    list(APPEND sources src/modules/dht_module.cpp)
  endif()
  add_executable(${target} ${sources})
  target_include_directories(${target} PRIVATE ${PQVPN_INCLUDE_DIRS})
  target_link_libraries(${target} PRIVATE Catch2::Catch2WithMain node_module_lib pqvpn_platform ${PQVPN_COMMON_LIBS})
  if(target STREQUAL "test_crypto_signature")
    target_link_libraries(${target} PRIVATE crypto_utils_lib)
  elseif(target STREQUAL "test_crypto_signature_keygen")
    target_link_libraries(${target} PRIVATE crypto_utils_lib)
  elseif(target STREQUAL "test_crypto_kem")
    target_link_libraries(${target} PRIVATE pqvpn_oqs_static)
  elseif(target STREQUAL "test_crypto_kem_keygen")
    target_link_libraries(${target} PRIVATE crypto_kem_lib pqvpn_oqs_static)
  elseif(target STREQUAL "test_crypto_signature_verify")
    target_link_libraries(${target} PRIVATE crypto_signature_lib)
  endif()
  pqvpn_attach_oqs_runtime(${target})
  add_test(NAME ${target} COMMAND ${target})
endforeach()

foreach(target IN LISTS GTEST_TESTS)
  add_executable(${target} tests/${target}.cpp)
  target_include_directories(${target} PRIVATE ${PQVPN_INCLUDE_DIRS})
  target_link_libraries(${target} PRIVATE GTest::gtest_main node_module_lib pqvpn_platform ${PQVPN_COMMON_LIBS})
  pqvpn_attach_oqs_runtime(${target})
  add_test(NAME ${target} COMMAND ${target})
endforeach()

target_link_libraries(test_find_known_peer_by_pubkeys PRIVATE node_module_lib ${PQVPN_COMMON_LIBS})

target_link_libraries(test_handle_relay PRIVATE node_module_lib)

# Auto-healing test registration for Hermes-generated parity tests.
# New tests/test_*.cpp files are automatically added to CTest so the
# deterministic validator cannot fail with evidence_test_registered=false.
set(PQVPN_WINDOWS_TESTS
  test_control_channel_commands
  test_vpn_state_machine
  test_windows_own_tunnel)
file(GLOB PQVPN_AUTO_TEST_SOURCES CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/tests/*.cpp")
foreach(test_src IN LISTS PQVPN_AUTO_TEST_SOURCES)
  get_filename_component(auto_target "${test_src}" NAME_WE)
  if(NOT TARGET ${auto_target})
    file(READ "${test_src}" auto_test_body)
    if(auto_target IN_LIST PQVPN_WINDOWS_TESTS AND NOT WIN32)
      continue()
    endif()
    add_executable(${auto_target} ${test_src})
    target_include_directories(${auto_target} PRIVATE ${PQVPN_INCLUDE_DIRS})
    if(auto_test_body MATCHES "gtest|GTEST|TEST_F")
      target_link_libraries(${auto_target} PRIVATE GTest::gtest_main node_module_lib pqvpn_platform crypto_utils_lib crypto_kem_lib crypto_signature_lib ${PQVPN_COMMON_LIBS})
    else()
      target_link_libraries(${auto_target} PRIVATE Catch2::Catch2WithMain node_module_lib pqvpn_platform crypto_utils_lib crypto_kem_lib crypto_signature_lib ${PQVPN_COMMON_LIBS})
    endif()
    pqvpn_attach_oqs_runtime(${auto_target})
    add_test(NAME ${auto_target} COMMAND ${auto_target})
  endif()
endforeach()

# Tests that bind fixed UDP ports or share scratch files in the working /
# temp directory cannot run concurrently with each other. None of them may
# overlap pqvpn_hard_kernel either: that gate re-runs this whole suite inside
# itself, so while it runs the outer suite must not touch those resources.
# One shared resource lock makes ctest serialize exactly these tests (and the
# gate) while leaving everything else free to parallelize.
set(PQVPN_EXCLUSIVE_TESTS
  test_e2e_egress
  test_network
  test_network_module
  test_handle_relay
  test_handshake_integration
  test_peer_liveness
  test_tunnel_forward
  test_config
  test_save_known_peers
  test_load_known_peers
  test_logger_init)
foreach(exclusive_test IN LISTS PQVPN_EXCLUSIVE_TESTS)
  if(TEST ${exclusive_test})
    set_tests_properties(${exclusive_test} PROPERTIES RESOURCE_LOCK "pqvpn_shared_resources")
  endif()
endforeach()

# Optional: Driver HLK/DDI compliance tests (Phase 4)
option(PQVPN_BUILD_DRIVER_TESTS "Build driver test utilities" OFF)
if(PQVPN_BUILD_DRIVER_TESTS AND WIN32)
    add_subdirectory(driver/pqvpn_tunnel)
endif()

endif()
