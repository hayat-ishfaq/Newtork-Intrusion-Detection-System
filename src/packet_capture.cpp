#include "packet_capture.hpp"
#include "utils.hpp"
#include <iostream>
#include <cstring>
#include <thread>
#include <iomanip>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#endif

// Initialize static constants
const std::string PacketCapture::DEFAULT_FILTER = "port 53";

PacketCapture::PacketCapture() 
    : pcap_handle_(nullptr)
    , promiscuous_mode_(true)
    , buffer_size_mb_(DEFAULT_BUFFER_SIZE_MB)
    , timeout_ms_(DEFAULT_TIMEOUT_MS)
    , is_capturing_(false) {
    
    std::memset(error_buffer_, 0, PCAP_ERRBUF_SIZE);
    dns_parser_ = std::make_unique<DNSParser>();
    stats_.reset();
}

PacketCapture::~PacketCapture() {
    stopCapture();
    
    if (pcap_handle_) {
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
    }
}

std::vector<NetworkInterface> PacketCapture::getAvailableInterfaces() {
    std::vector<NetworkInterface> interfaces;
    
    pcap_if_t* all_devs = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    if (pcap_findalldevs(&all_devs, errbuf) == -1) {
        last_error_ = "Error finding devices: " + std::string(errbuf);
        return interfaces;
    }
    
    for (pcap_if_t* dev = all_devs; dev != nullptr; dev = dev->next) {
        NetworkInterface interface;
        interface.name = dev->name;
        interface.description = dev->description ? dev->description : "No description";
        interface.is_up = (dev->flags & PCAP_IF_UP) != 0;
        interface.is_loopback = (dev->flags & PCAP_IF_LOOPBACK) != 0;
        
        // Get first address if available
        if (dev->addresses) {
            struct sockaddr_in* addr_in = (struct sockaddr_in*)dev->addresses->addr;
            if (addr_in && addr_in->sin_family == AF_INET) {
                interface.address = inet_ntoa(addr_in->sin_addr);
            }
        }
        
        interfaces.push_back(interface);
    }
    
    pcap_freealldevs(all_devs);
    return interfaces;
}

bool PacketCapture::setInterface(const std::string& interface_name) {
    interface_name_ = interface_name;
    return true;
}

bool PacketCapture::setFilter(const std::string& filter_expression) {
    filter_expression_ = filter_expression;
    
    // If we have an active capture, apply the filter immediately
    if (pcap_handle_) {
        struct bpf_program fp;
        if (pcap_compile(pcap_handle_, &fp, filter_expression.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
            last_error_ = "Error compiling filter: " + std::string(pcap_geterr(pcap_handle_));
            return false;
        }
        
        if (pcap_setfilter(pcap_handle_, &fp) == -1) {
            last_error_ = "Error setting filter: " + std::string(pcap_geterr(pcap_handle_));
            pcap_freecode(&fp);
            return false;
        }
        
        pcap_freecode(&fp);
    }
    
    return true;
}

bool PacketCapture::setPromiscuousMode(bool enable) {
    promiscuous_mode_ = enable;
    return true;
}

bool PacketCapture::setBufferSize(int size_mb) {
    buffer_size_mb_ = size_mb;
    return true;
}

bool PacketCapture::setTimeout(int timeout_ms) {
    timeout_ms_ = timeout_ms;
    return true;
}

bool PacketCapture::openPcapFile(const std::string& filename) {
    if (pcap_handle_) {
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
    }
    
    pcap_handle_ = pcap_open_offline(filename.c_str(), error_buffer_);
    if (!pcap_handle_) {
        last_error_ = "Error opening pcap file: " + std::string(error_buffer_);
        return false;
    }
    
    // Apply filter if set
    if (!filter_expression_.empty()) {
        struct bpf_program fp;
        if (pcap_compile(pcap_handle_, &fp, filter_expression_.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
            last_error_ = "Error compiling filter: " + std::string(pcap_geterr(pcap_handle_));
            pcap_close(pcap_handle_);
            pcap_handle_ = nullptr;
            return false;
        }
        
        if (pcap_setfilter(pcap_handle_, &fp) == -1) {
            last_error_ = "Error setting filter: " + std::string(pcap_geterr(pcap_handle_));
            pcap_freecode(&fp);
            pcap_close(pcap_handle_);
            pcap_handle_ = nullptr;
            return false;
        }
        
        pcap_freecode(&fp);
    }
    
    return true;
}

bool PacketCapture::startLiveCapture() {
    if (interface_name_.empty()) {
        last_error_ = "No interface specified";
        return false;
    }
    
    if (pcap_handle_) {
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
    }
    
    // Open the capture device
    pcap_handle_ = pcap_open_live(interface_name_.c_str(), 
                                  buffer_size_mb_ * 1024 * 1024,  // Convert MB to bytes
                                  promiscuous_mode_ ? 1 : 0,
                                  timeout_ms_,
                                  error_buffer_);
    
    if (!pcap_handle_) {
        last_error_ = "Error opening device: " + std::string(error_buffer_);
        return false;
    }
    
    // Set filter
    std::string filter = filter_expression_.empty() ? DEFAULT_FILTER : filter_expression_;
    if (!setFilter(filter)) {
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
        return false;
    }
    
    stats_.reset();
    is_capturing_ = true;
    
    std::cout << "Started capture on interface: " << interface_name_ << std::endl;
    std::cout << "Using filter: " << filter << std::endl;
    
    return true;
}

bool PacketCapture::stopCapture() {
    is_capturing_ = false;
    
    if (capture_thread_.joinable()) {
        capture_thread_.join();
    }
    
    if (pcap_handle_) {
        pcap_breakloop(pcap_handle_);
    }
    
    return true;
}

void PacketCapture::setPacketCallback(PacketCallback callback) {
    packet_callback_ = callback;
}

void PacketCapture::processPackets(int max_packets) {
    if (!pcap_handle_) {
        last_error_ = "No capture handle available";
        return;
    }
    
    if (is_capturing_ && !capture_thread_.joinable()) {
        // Start capture in separate thread for live capture
        capture_thread_ = std::thread([this, max_packets]() {
            pcap_loop(pcap_handle_, max_packets, packetHandler, reinterpret_cast<u_char*>(this));
        });
    } else {
        // Process packets synchronously for file-based capture
        pcap_loop(pcap_handle_, max_packets, packetHandler, reinterpret_cast<u_char*>(this));
    }
}

void PacketCapture::packetHandler(u_char* user_data, 
                                  const struct pcap_pkthdr* packet_header,
                                  const u_char* packet_data) {
    PacketCapture* capture = reinterpret_cast<PacketCapture*>(user_data);
    capture->processPacket(packet_header, packet_data);
}

void PacketCapture::processPacket(const struct pcap_pkthdr* packet_header,
                                  const u_char* packet_data) {
    stats_.total_packets++;
    
    // Parse Ethernet frame
    const u_char* ip_data = nullptr;
    size_t ip_len = 0;
    
    if (!parseEthernetFrame(packet_data, packet_header->caplen, ip_data, ip_len)) {
        stats_.invalid_packets++;
        return;
    }
    
    // Parse IP packet
    std::string src_ip, dst_ip;
    const u_char* transport_data = nullptr;
    size_t transport_len = 0;
    uint8_t protocol = 0;
    
    if (!parseIPPacket(ip_data, ip_len, src_ip, dst_ip, transport_data, transport_len, protocol)) {
        stats_.invalid_packets++;
        return;
    }
    
    // Parse transport layer (UDP or TCP)
    uint16_t src_port = 0, dst_port = 0;
    const u_char* payload_data = nullptr;
    size_t payload_len = 0;
    
    bool transport_ok = false;
    if (protocol == 17) { // UDP
        transport_ok = parseUDPPacket(transport_data, transport_len, src_port, dst_port, payload_data, payload_len);
    } else if (protocol == 6) { // TCP
        transport_ok = parseTCPPacket(transport_data, transport_len, src_port, dst_port, payload_data, payload_len);
    }
    
    if (!transport_ok) {
        stats_.invalid_packets++;
        return;
    }
    
    // Check if it's DNS traffic
    if (!isDNSPort(src_port) && !isDNSPort(dst_port)) {
        return;
    }
    
    // Parse DNS packet
    uint64_t timestamp = static_cast<uint64_t>(packet_header->ts.tv_sec) * 1000000 + packet_header->ts.tv_usec;
    
    auto dns_packet = dns_parser_->parseDNSPacket(payload_data, payload_len, src_ip, dst_ip, src_port, dst_port, timestamp);
    
    if (!dns_packet) {
        stats_.invalid_packets++;
        return;
    }
    
    stats_.dns_packets++;
    
    // Call user callback if set
    if (packet_callback_) {
        packet_callback_(*dns_packet);
    }
}

bool PacketCapture::parseEthernetFrame(const u_char* packet_data, size_t packet_len,
                                       const u_char*& ip_data, size_t& ip_len) {
    if (packet_len < ETHERNET_HEADER_SIZE) {
        return false;
    }
    
    // Skip Ethernet header (14 bytes)
    ip_data = packet_data + ETHERNET_HEADER_SIZE;
    ip_len = packet_len - ETHERNET_HEADER_SIZE;
    
    return true;
}

bool PacketCapture::parseIPPacket(const u_char* ip_data, size_t ip_len,
                                  std::string& src_ip, std::string& dst_ip,
                                  const u_char*& transport_data, size_t& transport_len,
                                  uint8_t& protocol) {
    if (ip_len < IP_HEADER_MIN_SIZE) {
        return false;
    }
    
    // Check IP version
    uint8_t version = (ip_data[0] >> 4) & 0x0F;
    if (version != 4) { // Only IPv4 for now
        return false;
    }
    
    // Get header length
    uint8_t header_len = (ip_data[0] & 0x0F) * 4;
    if (header_len < IP_HEADER_MIN_SIZE || header_len > ip_len) {
        return false;
    }
    
    // Get protocol
    protocol = ip_data[9];
    
    // Get source and destination IP addresses
    uint32_t src_addr = *reinterpret_cast<const uint32_t*>(ip_data + 12);
    uint32_t dst_addr = *reinterpret_cast<const uint32_t*>(ip_data + 16);
    
    src_ip = formatIPAddress(src_addr);
    dst_ip = formatIPAddress(dst_addr);
    
    // Get transport layer data
    transport_data = ip_data + header_len;
    transport_len = ip_len - header_len;
    
    return true;
}

bool PacketCapture::parseUDPPacket(const u_char* udp_data, size_t udp_len,
                                   uint16_t& src_port, uint16_t& dst_port,
                                   const u_char*& payload_data, size_t& payload_len) {
    if (udp_len < UDP_HEADER_SIZE) {
        return false;
    }
    
    src_port = NetworkUtils::networkToHost16(*reinterpret_cast<const uint16_t*>(udp_data));
    dst_port = NetworkUtils::networkToHost16(*reinterpret_cast<const uint16_t*>(udp_data + 2));
    
    payload_data = udp_data + UDP_HEADER_SIZE;
    payload_len = udp_len - UDP_HEADER_SIZE;
    
    return true;
}

bool PacketCapture::parseTCPPacket(const u_char* tcp_data, size_t tcp_len,
                                   uint16_t& src_port, uint16_t& dst_port,
                                   const u_char*& payload_data, size_t& payload_len) {
    if (tcp_len < TCP_HEADER_MIN_SIZE) {
        return false;
    }
    
    src_port = NetworkUtils::networkToHost16(*reinterpret_cast<const uint16_t*>(tcp_data));
    dst_port = NetworkUtils::networkToHost16(*reinterpret_cast<const uint16_t*>(tcp_data + 2));
    
    // Get TCP header length
    uint8_t header_len = ((tcp_data[12] >> 4) & 0x0F) * 4;
    if (header_len < TCP_HEADER_MIN_SIZE || header_len > tcp_len) {
        return false;
    }
    
    payload_data = tcp_data + header_len;
    payload_len = tcp_len - header_len;
    
    return true;
}

std::string PacketCapture::formatIPAddress(uint32_t ip_addr) {
    return NetworkUtils::formatIPv4Address(ip_addr);
}

void PacketCapture::printStatistics() const {
    std::cout << "\n=== Packet Capture Statistics ===" << std::endl;
    std::cout << "Total packets captured: " << stats_.total_packets << std::endl;
    std::cout << "DNS packets processed: " << stats_.dns_packets << std::endl;
    std::cout << "Invalid packets: " << stats_.invalid_packets << std::endl;
    std::cout << "Packets per second: " << std::fixed << std::setprecision(2) 
              << stats_.getPacketsPerSecond() << std::endl;
    
    // Get libpcap statistics if available
    if (pcap_handle_) {
        struct pcap_stat pcap_statistics;
        if (pcap_stats(pcap_handle_, &pcap_statistics) == 0) {
            std::cout << "Packets received by filter: " << pcap_statistics.ps_recv << std::endl;
            std::cout << "Packets dropped by kernel: " << pcap_statistics.ps_drop << std::endl;
        }
    }
}
