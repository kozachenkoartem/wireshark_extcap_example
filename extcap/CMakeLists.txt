CMAKE_MINIMUM_REQUIRED(VERSION 3.13)

PROJECT(extcap_example)

SET(CMAKE_AUTOMOC OFF)

add_executable(extcapdump
utils.cpp
extcapdump.cpp
)

INSTALL(TARGETS extcapdump DESTINATION ${Wireshark_LIB_DIR}/wireshark/extcap)
INSTALL(PROGRAMS extcap.py DESTINATION ${Wireshark_LIB_DIR}/wireshark/extcap)