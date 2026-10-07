vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO open-quantum-safe/liboqs
    REF ${VERSION}
    SHA512 492cefb8773f5736a11984c951dbbffde555a16d0599d417fdb008627d2ff0efd5742294be7e4936ad6836b5c7dc3c32e2f4537bf1e8dd4deb5ac5f4be87a974
)

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
        -DOQS_BUILD_ONLY_LIB=ON
        -DOQS_PERMIT_UNSUPPORTED_ARCHITECTURE=ON
        "-DOQS_MINIMAL_BUILD=KEM_ml_kem_1024;SIG_ml_dsa_87"
)

vcpkg_cmake_install()
vcpkg_copy_pdbs()
vcpkg_cmake_config_fixup(CONFIG_PATH "lib/cmake/${PORT}")
vcpkg_fixup_pkgconfig()

file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include")
file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/share")

vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/LICENSE.txt")
