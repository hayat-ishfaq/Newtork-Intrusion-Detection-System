#ifndef DETECTOR_HPP
#define DETECTOR_HPP

#include "dns_parser.hpp"
#include <unordered_map>
#include <chrono>
#include <memory>
#include <vector>
#include <string>

// Rule structure
struct DNSRule {
    std::string id;
    std::string description;
    std::string condition;
    std::string severity;
    bool enabled;
};

// Alert structure
struct DNSAlert {
    std::string rule_id;
    std::string severity;
    std::string description;
    std::string source_ip;
    std::string dest_ip;
    std::string query_name;
    uint16_t query_type;
    uint64_t timestamp;
    std::string details;
};

// Traffic statistics for anomaly detection
struct TrafficStats {
    uint32_t query_count;
    uint32_t nxdomain_count;
    uint32_t large_response_count;
    std::chrono::steady_clock::time_point last_reset;
    std::unordered_map<uint16_t, uint32_t> query_type_counts;
    std::unordered_map<std::string, uint32_t> domain_counts;
};

// IP-based statistics
struct IPStats {
    uint32_t total_queries;
    uint32_t queries_per_window;
    uint32_t nxdomain_responses;
    std::chrono::steady_clock::time_point window_start;
    std::vector<uint32_t> query_history; // Rolling window
    double baseline_rate;
    bool baseline_established;
};

class DNSDetector {
public:
    DNSDetector();
    ~DNSDetector();
    
    // Initialization
    bool loadRules(const std::string& rules_file);
    bool initializeLogging(const std::string& log_file);
    
    // Main detection functions
    std::vector<DNSAlert> analyzePacket(const DNSPacket& packet);
    void updateStatistics(const DNSPacket& packet);
    
    // Detection methods
    std::vector<DNSAlert> checkRuleBasedDetection(const DNSPacket& packet);
    std::vector<DNSAlert> checkAnomalyDetection(const DNSPacket& packet);
    
    // Rule-based detection rules
    bool checkMalformedDNS(const DNSPacket& packet, DNSAlert& alert);
    bool checkLongDomain(const DNSPacket& packet, DNSAlert& alert);
    bool checkSuspiciousQueryTypes(const DNSPacket& packet, DNSAlert& alert);
    bool checkDNSFlooding(const DNSPacket& packet, DNSAlert& alert);
    bool checkDNSTunneling(const DNSPacket& packet, DNSAlert& alert);
    bool checkDGADetection(const DNSPacket& packet, DNSAlert& alert);
    
    // Anomaly detection
    bool checkVolumeSpike(const DNSPacket& packet, DNSAlert& alert);
    bool checkNXDomainBurst(const DNSPacket& packet, DNSAlert& alert);
    bool checkUnusualQueryPattern(const DNSPacket& packet, DNSAlert& alert);
    
    // Alert handling
    void logAlert(const DNSAlert& alert);
    void forwardAlert(const DNSAlert& alert);
    
    // Statistics
    void printStatistics() const;
    void resetStatistics();
    
    // Configuration
    void setAnomalyThreshold(double threshold) { anomaly_threshold_ = threshold; }
    void setTimeWindow(int seconds) { time_window_seconds_ = seconds; }
    void setBaselineWindow(int packets) { baseline_window_size_ = packets; }
    
private:
    // Rule management
    std::vector<DNSRule> rules_;
    bool parseRulesFromJson(const std::string& json_content);
    
    // Statistics tracking
    std::unordered_map<std::string, IPStats> ip_stats_;
    TrafficStats global_stats_;
    
    // Anomaly detection parameters
    double anomaly_threshold_;
    int time_window_seconds_;
    int baseline_window_size_;
    
    // Logging
    std::string log_file_path_;
    bool logging_enabled_;
    
    // Helper functions
    bool isDGA(const std::string& domain) const;
    double calculateEntropy(const std::string& str) const;
    bool containsSuspiciousPatterns(const std::string& domain) const;
    std::string getCurrentTimestamp() const;
    void updateIPStats(const std::string& ip, const DNSPacket& packet);
    void updateBaseline(const std::string& ip);
    bool isRareQueryType(uint16_t qtype) const;
    
    // Constants
    static const uint32_t MAX_QUERIES_PER_SECOND = 1000;
    static const size_t MAX_DOMAIN_LENGTH = 100;
    static const size_t MIN_DGA_DOMAIN_LENGTH = 10;
    static const double DGA_ENTROPY_THRESHOLD;
    static const std::vector<uint16_t> RARE_QUERY_TYPES;
};

#endif // DETECTOR_HPP
