cmake_minimum_required(VERSION 3.10)
project(NIDS_DNS VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Set build type if not specified
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler flags
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -DDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")

# Add compiler warnings
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Find required packages
find_package(PkgConfig REQUIRED)

# Find libpcap
if(WIN32)
    # For Windows, you may need to set PCAP_ROOT to WinPcap/Npcap installation directory
    find_path(PCAP_INCLUDE_DIR pcap.h
        HINTS ${PCAP_ROOT}/Include
        PATH_SUFFIXES pcap)
    
    find_library(PCAP_LIBRARIES
        NAMES wpcap pcap
        HINTS ${PCAP_ROOT}/Lib ${PCAP_ROOT}/Lib/x64
        PATH_SUFFIXES lib)
        
    # Find winsock2 for Windows
    set(WINSOCK_LIBRARIES ws2_32)
else()
    # For Unix-like systems
    pkg_check_modules(PCAP REQUIRED libpcap)
    if(NOT PCAP_FOUND)
        find_path(PCAP_INCLUDE_DIR pcap.h)
        find_library(PCAP_LIBRARIES pcap)
        # Check if pcap was found via find_path/find_library
        if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARIES)
            message(FATAL_ERROR "libpcap not found! Please install libpcap development package.")
        endif()
    else()
        # pkg-config found libpcap, use its variables
        set(PCAP_INCLUDE_DIR ${PCAP_INCLUDE_DIRS})
        set(PCAP_LIBRARIES ${PCAP_LIBRARIES})
    endif()
endif()

message(STATUS "Found libpcap: ${PCAP_LIBRARIES}")
message(STATUS "libpcap include dir: ${PCAP_INCLUDE_DIR}")

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${PCAP_INCLUDE_DIR})

# Source files
set(SOURCES
    src/main.cpp
    src/dns_parser.cpp
    src/detector.cpp
    src/packet_capture.cpp
    src/utils.cpp
)

# Header files
set(HEADERS
    include/dns_parser.hpp
    include/detector.hpp
    include/packet_capture.hpp
    include/utils.hpp
)

# Create main executable
add_executable(nids_dns ${SOURCES} ${HEADERS})

# Link libraries
target_link_libraries(nids_dns ${PCAP_LIBRARIES})

if(WIN32)
    target_link_libraries(nids_dns ${WINSOCK_LIBRARIES})
endif()

# Test executable
set(TEST_SOURCES
    tests/test_dns_parser.cpp
    src/dns_parser.cpp
    src/detector.cpp
    src/utils.cpp
)

add_executable(test_nids_dns ${TEST_SOURCES})
target_link_libraries(test_nids_dns ${PCAP_LIBRARIES})

if(WIN32)
    target_link_libraries(test_nids_dns ${WINSOCK_LIBRARIES})
endif()

# Installation
install(TARGETS nids_dns DESTINATION bin)
install(FILES rules/dns_rules.json DESTINATION share/nids_dns/rules)
install(DIRECTORY docs/ DESTINATION share/nids_dns/docs)

# Custom target to create sample PCAP files (requires tcpdump or similar)
add_custom_target(sample_pcaps
    COMMAND ${CMAKE_COMMAND} -E echo "Creating sample PCAP files..."
    COMMENT "Generate sample PCAP files for testing"
)

# Custom target to run tests
add_custom_target(run_tests
    COMMAND test_nids_dns
    DEPENDS test_nids_dns
    COMMENT "Running unit tests"
)

# Custom target to run with sample data
add_custom_target(test_run
    COMMAND nids_dns -r ${CMAKE_SOURCE_DIR}/tests/dns/normal.pcap -R ${CMAKE_SOURCE_DIR}/rules/dns_rules.json -v
    DEPENDS nids_dns
    COMMENT "Running NIDS with sample data"
)

# Package configuration
set(CPACK_PACKAGE_NAME "nids_dns")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "DNS Network Intrusion Detection System")
set(CPACK_PACKAGE_VENDOR "Security Research")
set(CPACK_PACKAGE_CONTACT "security@example.com")

if(WIN32)
    set(CPACK_GENERATOR "ZIP;NSIS")
else()
    set(CPACK_GENERATOR "TGZ;DEB;RPM")
endif()

include(CPack)

# Print build information
message(STATUS "")
message(STATUS "=== Build Configuration ===")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "Install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "libpcap libraries: ${PCAP_LIBRARIES}")
if(WIN32)
    message(STATUS "Winsock libraries: ${WINSOCK_LIBRARIES}")
endif()
message(STATUS "")
message(STATUS "=== Build Targets ===")
message(STATUS "  nids_dns        - Main NIDS application")
message(STATUS "  test_nids_dns   - Unit tests")
message(STATUS "  run_tests       - Run unit tests")
message(STATUS "  sample_pcaps    - Generate sample PCAP files")
message(STATUS "  test_run        - Test run with sample data")
message(STATUS "")
message(STATUS "=== Usage ===")
message(STATUS "  make             - Build all targets")
message(STATUS "  make run_tests   - Build and run tests")
message(STATUS "  make install     - Install to system")
message(STATUS "  make package     - Create distribution package")
message(STATUS "")
