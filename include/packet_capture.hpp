#ifndef PACKET_CAPTURE_HPP
#define PACKET_CAPTURE_HPP

#include "dns_parser.hpp"
#include "detector.hpp"
#include <pcap.h>
#include <string>
#include <memory>
#include <functional>
#include <atomic>
#include <thread>

// Packet callback function type
using PacketCallback = std::function<void(const DNSPacket&)>;

// Network interface information
struct NetworkInterface {
    std::string name;
    std::string description;
    std::string address;
    bool is_up;
    bool is_loopback;
};

// Capture statistics
struct CaptureStats {
    uint64_t total_packets;
    uint64_t dns_packets;
    uint64_t dropped_packets;
    uint64_t invalid_packets;
    std::chrono::steady_clock::time_point start_time;
    
    void reset() {
        total_packets = 0;
        dns_packets = 0;
        dropped_packets = 0;
        invalid_packets = 0;
        start_time = std::chrono::steady_clock::now();
    }
    
    double getPacketsPerSecond() const {
        auto now = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - start_time);
        return duration.count() > 0 ? static_cast<double>(total_packets) / duration.count() : 0.0;
    }
};

class PacketCapture {
public:
    PacketCapture();
    ~PacketCapture();
    
    // Interface management
    std::vector<NetworkInterface> getAvailableInterfaces();
    bool setInterface(const std::string& interface_name);
    
    // Capture configuration
    bool setFilter(const std::string& filter_expression);
    bool setPromiscuousMode(bool enable);
    bool setBufferSize(int size_mb);
    bool setTimeout(int timeout_ms);
    
    // File-based capture
    bool openPcapFile(const std::string& filename);
    bool saveToPcapFile(const std::string& filename);
    
    // Live capture
    bool startLiveCapture();
    bool stopCapture();
    bool isCapturing() const { return is_capturing_; }
    
    // Packet processing
    void setPacketCallback(PacketCallback callback);
    void processPackets(int max_packets = -1); // -1 for unlimited
    
    // Statistics
    CaptureStats getStatistics() const { return stats_; }
    void printStatistics() const;
    void resetStatistics() { stats_.reset(); }
    
    // Error handling
    std::string getLastError() const { return last_error_; }
    
private:
    // libpcap handles
    pcap_t* pcap_handle_;
    char error_buffer_[PCAP_ERRBUF_SIZE];
    
    // Configuration
    std::string interface_name_;
    std::string filter_expression_;
    bool promiscuous_mode_;
    int buffer_size_mb_;
    int timeout_ms_;
    
    // State
    std::atomic<bool> is_capturing_;
    std::string last_error_;
    
    // Statistics
    mutable CaptureStats stats_;
    
    // DNS parser and detector
    std::unique_ptr<DNSParser> dns_parser_;
    PacketCallback packet_callback_;
    
    // Packet processing thread
    std::thread capture_thread_;
    
    // Internal callback functions
    static void packetHandler(u_char* user_data, 
                             const struct pcap_pkthdr* packet_header,
                             const u_char* packet_data);
    
    void processPacket(const struct pcap_pkthdr* packet_header,
                      const u_char* packet_data);
    
    // Network packet parsing
    bool parseEthernetFrame(const u_char* packet_data, size_t packet_len,
                           const u_char*& ip_data, size_t& ip_len);
    
    bool parseIPPacket(const u_char* ip_data, size_t ip_len,
                      std::string& src_ip, std::string& dst_ip,
                      const u_char*& transport_data, size_t& transport_len,
                      uint8_t& protocol);
    
    bool parseUDPPacket(const u_char* udp_data, size_t udp_len,
                       uint16_t& src_port, uint16_t& dst_port,
                       const u_char*& payload_data, size_t& payload_len);
    
    bool parseTCPPacket(const u_char* tcp_data, size_t tcp_len,
                       uint16_t& src_port, uint16_t& dst_port,
                       const u_char*& payload_data, size_t& payload_len);
    
    // Utility functions
    std::string formatIPAddress(uint32_t ip_addr);
    uint16_t parsePort(const u_char* data, size_t offset);
    bool isDNSPort(uint16_t port) const { return port == 53; }
    
    // Constants
    static const std::string DEFAULT_FILTER;
    static const int DEFAULT_BUFFER_SIZE_MB = 2;
    static const int DEFAULT_TIMEOUT_MS = 1000;
    static const size_t ETHERNET_HEADER_SIZE = 14;
    static const size_t IP_HEADER_MIN_SIZE = 20;
    static const size_t UDP_HEADER_SIZE = 8;
    static const size_t TCP_HEADER_MIN_SIZE = 20;
};

#endif // PACKET_CAPTURE_HPP
