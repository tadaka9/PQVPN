cmake_minimum_required(VERSION 3.28)
project(PQVPNMobile VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt6 6.7 REQUIRED COMPONENTS Core Gui Quick QuickControls2)
qt_standard_project_setup(REQUIRES 6.7)

qt_add_executable(pqvpn_mobile main.cpp)
qt_add_qml_module(pqvpn_mobile
  URI PQVPN.Mobile
  VERSION 1.0
  QML_FILES Main.qml)

target_link_libraries(pqvpn_mobile PRIVATE
  Qt6::Core Qt6::Gui Qt6::Quick Qt6::QuickControls2)

set_target_properties(pqvpn_mobile PROPERTIES
  MACOSX_BUNDLE TRUE
  MACOSX_BUNDLE_GUI_IDENTIFIER io.github.tadaka9.pqvpn.mobile
  MACOSX_BUNDLE_BUNDLE_NAME "PQVPN Mobile Preview"
  MACOSX_BUNDLE_SHORT_VERSION_STRING "${PROJECT_VERSION}"
  MACOSX_BUNDLE_BUNDLE_VERSION "${PROJECT_VERSION}"
  QT_ANDROID_PACKAGE_NAME io.github.tadaka9.pqvpn
  QT_ANDROID_COMPILE_SDK_VERSION 35
  QT_ANDROID_MIN_SDK_VERSION 28)

install(TARGETS pqvpn_mobile
  BUNDLE DESTINATION .
  LIBRARY DESTINATION lib
  RUNTIME DESTINATION bin)
