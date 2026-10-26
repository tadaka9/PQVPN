cmake_minimum_required(VERSION 3.28)
project(PQVPNMobile VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt6 6.7 REQUIRED COMPONENTS Core Gui Quick QuickControls2)
qt_standard_project_setup(REQUIRES 6.7)

set(PQVPN_UI_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../ui")
set(PQVPN_UI_QML "${PQVPN_UI_DIR}/Main.qml")
set_source_files_properties("${PQVPN_UI_QML}" PROPERTIES QT_RESOURCE_ALIAS Main.qml)

# pqvpn_mobile is the package target name only. Desktop and mobile load the
# same PQVPN.App module and the same QML source; platform code remains below UI.
qt_add_executable(pqvpn_mobile "${PQVPN_UI_DIR}/main.cpp")
qt_add_qml_module(pqvpn_mobile
  URI PQVPN.App
  VERSION 1.0
  QML_FILES "${PQVPN_UI_QML}")

target_link_libraries(pqvpn_mobile PRIVATE
  Qt6::Core Qt6::Gui Qt6::Quick Qt6::QuickControls2)

if(ANDROID)
  target_link_options(pqvpn_mobile PRIVATE
    "-Wl,-z,max-page-size=16384"
    "-Wl,-z,common-page-size=16384")
endif()

set_target_properties(pqvpn_mobile PROPERTIES
  MACOSX_BUNDLE TRUE
  MACOSX_BUNDLE_GUI_IDENTIFIER io.github.tadaka9.pqvpn
  MACOSX_BUNDLE_BUNDLE_NAME "PQVPN"
  MACOSX_BUNDLE_SHORT_VERSION_STRING "${PROJECT_VERSION}"
  MACOSX_BUNDLE_BUNDLE_VERSION "${PROJECT_VERSION}"
  QT_ANDROID_PACKAGE_NAME io.github.tadaka9.pqvpn
  QT_ANDROID_COMPILE_SDK_VERSION 36
  QT_ANDROID_TARGET_SDK_VERSION 36
  QT_ANDROID_MIN_SDK_VERSION 28)

if(ANDROID)
  set_property(TARGET pqvpn_mobile PROPERTY
    QT_ANDROID_PACKAGE_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/android")
endif()

install(TARGETS pqvpn_mobile
  BUNDLE DESTINATION .
  LIBRARY DESTINATION lib
  RUNTIME DESTINATION bin)
