cmake_minimum_required(VERSION 3.15)
project(pqvpn_tunnel_tests C CXX)

# IRP Fuzzing Test
add_executable(irp_fuzz_test hlk_tests/irp_fuzz_test.cpp)
target_compile_features(irp_fuzz_test PRIVATE cxx_std_17)

if(MSVC)
    target_link_libraries(irp_fuzz_test PRIVATE kernel32 user32)
endif()

# Install test binaries
install(TARGETS irp_fuzz_test DESTINATION bin/tests)