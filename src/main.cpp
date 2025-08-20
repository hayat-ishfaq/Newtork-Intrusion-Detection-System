#include <iostream>
#include <memory>
#include <signal.h>
#include <cstring>
#include <thread>
#include <chrono>
#include <iomanip>

#ifdef _WIN32
#include <getopt.h>  // You may need to install getopt for Windows
#else
#include <getopt.h>
#endif

#include "dns_parser.hpp"
#include "detector.hpp"
#include "packet_capture.hpp"
#include "utils.hpp"

// Global variables for signal handling
std::unique_ptr<PacketCapture> g_capture;
std::unique_ptr<DNSDetector> g_detector;
bool g_running = true;

void signalHandler(int signal) {
    std::cout << "\nReceived signal " << signal << ". Shutting down..." << std::endl;
    g_running = false;
    
    if (g_capture) {
        g_capture->stopCapture();
    }
}

void printUsage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [OPTIONS]\n\n"
              << "DNS Network Intrusion Detection System\n\n"
              << "Options:\n"
              << "  -i, --interface INTERFACE  Network interface to capture from (required for live capture)\n"
              << "  -r, --read FILE           Read packets from PCAP file instead of live capture\n"
              << "  -f, --filter FILTER       BPF filter expression (default: 'port 53')\n"
              << "  -c, --config FILE         Configuration file path\n"
              << "  -R, --rules FILE          DNS rules file path (default: '../rules/dns_rules.json')\n"
              << "  -l, --log FILE            Alert log file path (default: 'alerts.log')\n"
              << "  -v, --verbose             Enable verbose output\n"
              << "  -s, --stats INTERVAL      Print statistics every INTERVAL seconds\n"
              << "  -h, --help                Show this help message\n\n"
              << "Examples:\n"
              << "  " << program_name << " -i eth0 -r ../rules/dns_rules.json\n"
              << "  " << program_name << " -r capture.pcap -l dns_alerts.log\n"
              << "  " << program_name << " -i wlan0 -f \"port 53 and host 8.8.8.8\" -v\n";
}

void printBanner() {
    std::cout << R"(
╔══════════════════════════════════════════════════════════════════════════════╗
║                          DNS Network Intrusion Detection System             ║
║                                     NIDS v1.0                               ║
╚══════════════════════════════════════════════════════════════════════════════╝
)" << std::endl;
}

void printAvailableInterfaces() {
    std::cout << "Available network interfaces:" << std::endl;
    
    PacketCapture temp_capture;
    auto interfaces = temp_capture.getAvailableInterfaces();
    
    if (interfaces.empty()) {
        std::cout << "  No interfaces found or insufficient privileges." << std::endl;
        return;
    }
    
    for (const auto& iface : interfaces) {
        std::cout << "  " << iface.name;
        if (!iface.description.empty()) {
            std::cout << " (" << iface.description << ")";
        }
        if (!iface.address.empty()) {
            std::cout << " [" << iface.address << "]";
        }
        if (iface.is_loopback) {
            std::cout << " [loopback]";
        }
        if (!iface.is_up) {
            std::cout << " [down]";
        }
        std::cout << std::endl;
    }
}

int main(int argc, char* argv[]) {
    // Configuration variables
    std::string interface_name;
    std::string pcap_file;
    std::string filter_expression = "port 53";
    std::string config_file;
    std::string rules_file = "../rules/dns_rules.json";
    std::string log_file = "alerts.log";
    bool verbose = false;
    int stats_interval = 0; // 0 means no periodic stats
    
    // Parse command line arguments
    static struct option long_options[] = {
        {"interface", required_argument, 0, 'i'},
        {"read",      required_argument, 0, 'r'},
        {"filter",    required_argument, 0, 'f'},
        {"config",    required_argument, 0, 'c'},
        {"rules",     required_argument, 0, 'R'},
        {"log",       required_argument, 0, 'l'},
        {"verbose",   no_argument,       0, 'v'},
        {"stats",     required_argument, 0, 's'},
        {"help",      no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    
    int option_index = 0;
    int c;
    
    while ((c = getopt_long(argc, argv, "i:r:f:c:R:l:vs:h", long_options, &option_index)) != -1) {
        switch (c) {
            case 'i':
                interface_name = optarg;
                break;
            case 'r':
                pcap_file = optarg;
                break;
            case 'f':
                filter_expression = optarg;
                break;
            case 'c':
                config_file = optarg;
                break;
            case 'R':
                rules_file = optarg;
                break;
            case 'l':
                log_file = optarg;
                break;
            case 'v':
                verbose = true;
                break;
            case 's':
                stats_interval = std::atoi(optarg);
                break;
            case 'h':
                printBanner();
                printUsage(argv[0]);
                return 0;
            case '?':
                std::cerr << "Unknown option. Use -h for help." << std::endl;
                return 1;
            default:
                return 1;
        }
    }
    
    // Print banner
    printBanner();
    
    // Load configuration if provided
    std::unique_ptr<ConfigManager> config;
    if (!config_file.empty()) {
        config = std::make_unique<ConfigManager>(config_file);
        if (verbose) {
            std::cout << "Loaded configuration from: " << config_file << std::endl;
        }
    }
    
    // Initialize DNS detector
    g_detector = std::make_unique<DNSDetector>();
    
    if (!g_detector->loadRules(rules_file)) {
        std::cerr << "Warning: Failed to load rules from " << rules_file << std::endl;
        std::cerr << "Using default rules." << std::endl;
    } else if (verbose) {
        std::cout << "Loaded detection rules from: " << rules_file << std::endl;
    }
    
    if (!g_detector->initializeLogging(log_file)) {
        std::cerr << "Warning: Failed to initialize logging to " << log_file << std::endl;
    } else if (verbose) {
        std::cout << "Alert logging enabled: " << log_file << std::endl;
    }
    
    // Initialize packet capture
    g_capture = std::make_unique<PacketCapture>();
    
    // Set up signal handlers
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    // Configure capture source
    bool live_capture = pcap_file.empty();
    
    if (live_capture) {
        if (interface_name.empty()) {
            std::cout << "No interface specified. Available interfaces:\n" << std::endl;
            printAvailableInterfaces();
            std::cout << "\nPlease specify an interface with -i option." << std::endl;
            return 1;
        }
        
        if (!g_capture->setInterface(interface_name)) {
            std::cerr << "Failed to set interface: " << g_capture->getLastError() << std::endl;
            return 1;
        }
        
        if (verbose) {
            std::cout << "Using network interface: " << interface_name << std::endl;
        }
    } else {
        if (!g_capture->openPcapFile(pcap_file)) {
            std::cerr << "Failed to open PCAP file: " << g_capture->getLastError() << std::endl;
            return 1;
        }
        
        if (verbose) {
            std::cout << "Reading from PCAP file: " << pcap_file << std::endl;
        }
    }
    
    // Set capture filter
    if (!g_capture->setFilter(filter_expression)) {
        std::cerr << "Failed to set filter: " << g_capture->getLastError() << std::endl;
        return 1;
    }
    
    if (verbose) {
        std::cout << "Using capture filter: " << filter_expression << std::endl;
    }
    
    // Set packet callback
    g_capture->setPacketCallback([&](const DNSPacket& packet) {
        if (verbose) {
            std::cout << "DNS packet: " << packet.source_ip << ":" << packet.source_port
                      << " -> " << packet.dest_ip << ":" << packet.dest_port;
            
            if (!packet.questions.empty()) {
                std::cout << " Query: " << packet.questions[0].qname 
                          << " (Type: " << packet.questions[0].qtype << ")";
            }
            
            std::cout << std::endl;
        }
        
        // Analyze packet for threats
        auto alerts = g_detector->analyzePacket(packet);
        
        // Alerts are automatically logged and forwarded by the detector
        if (!alerts.empty() && verbose) {
            std::cout << "Generated " << alerts.size() << " alert(s)" << std::endl;
        }
    });
    
    // Start capture
    if (live_capture) {
        if (!g_capture->startLiveCapture()) {
            std::cerr << "Failed to start live capture: " << g_capture->getLastError() << std::endl;
            return 1;
        }
        
        std::cout << "Starting live DNS monitoring..." << std::endl;
        std::cout << "Press Ctrl+C to stop." << std::endl;
    } else {
        std::cout << "Processing PCAP file..." << std::endl;
    }
    
    // Statistics tracking
    auto last_stats_time = std::chrono::steady_clock::now();
    
    // Main processing loop
    if (live_capture) {
        // For live capture, process packets in background
        g_capture->processPackets(); // Unlimited packets
        
        while (g_running) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            
            // Print periodic statistics
            if (stats_interval > 0) {
                auto now = std::chrono::steady_clock::now();
                auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - last_stats_time);
                
                if (duration.count() >= stats_interval) {
                    g_capture->printStatistics();
                    g_detector->printStatistics();
                    last_stats_time = now;
                }
            }
        }
    } else {
        // For file-based capture, process all packets and exit
        g_capture->processPackets(); // Process all packets in file
        
        std::cout << "Finished processing PCAP file." << std::endl;
    }
    
    // Print final statistics
    std::cout << "\n=== Final Statistics ===" << std::endl;
    g_capture->printStatistics();
    g_detector->printStatistics();
    
    std::cout << "\nDNS NIDS shutdown complete." << std::endl;
    
    return 0;
}
