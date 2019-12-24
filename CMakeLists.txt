# CMakeLists.txt
#
# Wireshark - Dissector example
# By Artem Kozachenko <kozachenko.artem@gmail.com>
#

cmake_minimum_required(VERSION 3.13)
project(wireshark-plugin-example)

option(FORCE_COLORED_OUTPUT "Always produce ANSI-colored output (GNU/Clang only)." TRUE)

if (${FORCE_COLORED_OUTPUT})
    if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
       add_compile_options(-fdiagnostics-color=always)
    elseif("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
       add_compile_options(-fcolor-diagnostics)
    endif()
endif()

INCLUDE(GNUInstallDirs)
#INCLUDE(3rdparty/cmake-uninstall/cmake/cmake-uninstall.cmake)
#INCLUDE(3rdparty/cmake-version4git/cmake/cmake-version4git.cmake)
#PROJECT_VERSION_FROM_GIT()

SET(CMAKE_AUTOMOC ON)
SET(CMAKE_AUTOUIC ON)

find_package(Wireshark REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_search_module(GLIB REQUIRED glib-2.0)
find_package(Qt5Core REQUIRED)
find_package(Qt5PrintSupport REQUIRED)
find_package(Qt5Widgets REQUIRED)


include_directories(
	${Wireshark_INCLUDE_DIR}
	${GLIB_INCLUDE_DIRS}
	${CMAKE_CURRENT_SOURCE_DIR}/src
)

set (SOURCES
	src/dissector.cpp
	src/plugin.c
)

set_source_files_properties(
	${SOURCES}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS} -Wno-write-strings -Wno-vla"
)

add_library(example MODULE ${SOURCES})

SET_TARGET_PROPERTIES(example PROPERTIES PREFIX "")
set(CMAKE_EXE_LINKER_FLAGS "-static-curlpp")

target_link_libraries(example
	${GLIB_LDFLAGS}
	Qt5::Core
	Qt5::PrintSupport
	Qt5::Widgets
)

INSTALL(TARGETS example
DESTINATION
	"${Wireshark_PLUGIN_INSTALL_DIR}/epan")
INSTALL(PROGRAMS extcap.py DESTINATION ${Wireshark_LIB_DIR}/wireshark/extcap)

