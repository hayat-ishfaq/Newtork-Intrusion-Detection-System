#!/bin/bash

# DNS NIDS Build Script
# Builds the DNS NIDS project with proper dependencies

echo "=== DNS NIDS Build Script ==="
echo ""

# Check for required tools
check_dependencies() {
    echo "Checking dependencies..."
    
    # Check for cmake
    if ! command -v cmake &> /dev/null; then
        echo "Error: cmake is required but not installed"
        exit 1
    fi
    
    # Check for compiler
    if ! command -v g++ &> /dev/null && ! command -v clang++ &> /dev/null; then
        echo "Error: C++ compiler (g++ or clang++) is required"
        exit 1
    fi
    
    # Check for libpcap
    if ! pkg-config --exists libpcap 2>/dev/null; then
        echo "Warning: libpcap development package may not be installed"
        echo "Please install with: sudo apt-get install libpcap-dev (Ubuntu/Debian)"
        echo "                 or: sudo yum install libpcap-devel (RHEL/CentOS)"
    fi
    
    echo "✓ Dependencies check completed"
}

# Build function
build_project() {
    echo ""
    echo "Building DNS NIDS..."
    
    # Create build directory
    if [ ! -d "build" ]; then
        mkdir build
    fi
    
    cd build
    
    # Configure with cmake
    echo "Configuring with CMake..."
    cmake .. -DCMAKE_BUILD_TYPE=Release
    
    if [ $? -ne 0 ]; then
        echo "Error: CMake configuration failed"
        exit 1
    fi
    
    # Build
    echo "Compiling..."
    make -j$(nproc 2>/dev/null || echo 2)
    
    if [ $? -ne 0 ]; then
        echo "Error: Build failed"
        exit 1
    fi
    
    echo "✓ Build completed successfully"
}

# Run tests
run_tests() {
    echo ""
    echo "Running unit tests..."
    
    if [ -f "test_nids_dns" ]; then
        ./test_nids_dns
        if [ $? -eq 0 ]; then
            echo "✓ All tests passed"
        else
            echo "⚠ Some tests failed"
        fi
    else
        echo "⚠ Test executable not found"
    fi
}

# Installation
install_project() {
    echo ""
    echo "Installing DNS NIDS..."
    
    # Install to system (requires root)
    if [ "$1" = "--install" ]; then
        sudo make install
        echo "✓ Installation completed"
    else
        echo "To install system-wide, run: $0 --install"
    fi
}

# Main execution
main() {
    check_dependencies
    build_project
    run_tests
    
    if [ "$1" = "--install" ]; then
        install_project --install
    fi
    
    echo ""
    echo "=== Build Summary ==="
    echo "Executable: build/nids_dns"
    echo "Test suite: build/test_nids_dns"
    echo "Configuration: rules/dns_rules.json"
    echo ""
    echo "Usage examples:"
    echo "  ./build/nids_dns -h                                    # Show help"
    echo "  sudo ./build/nids_dns -i eth0 -v                      # Live capture"
    echo "  ./build/nids_dns -r sample.pcap -R rules/dns_rules.json # File analysis"
    echo ""
}

# Execute main function
main "$@"
