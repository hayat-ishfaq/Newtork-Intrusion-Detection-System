#include "detector.hpp"
#include "utils.hpp"
#include <fstream>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <cmath>
#include <regex>

// Initialize static constants
const double DNSDetector::DGA_ENTROPY_THRESHOLD = 3.5;
const std::vector<uint16_t> DNSDetector::RARE_QUERY_TYPES = {10, 16, 255, 99, 100, 101};

DNSDetector::DNSDetector() 
    : anomaly_threshold_(3.0)
    , time_window_seconds_(60)
    , baseline_window_size_(100)
    , logging_enabled_(false) {
    
    // Initialize global statistics
    global_stats_.query_count = 0;
    global_stats_.nxdomain_count = 0;
    global_stats_.large_response_count = 0;
    global_stats_.last_reset = std::chrono::steady_clock::now();
}

DNSDetector::~DNSDetector() {
    // Cleanup
}

bool DNSDetector::loadRules(const std::string& rules_file) {
    try {
        std::string json_content = FileUtils::readTextFile(rules_file);
        if (json_content.empty()) {
            std::cerr << "Failed to read rules file: " << rules_file << std::endl;
            return false;
        }
        
        return parseRulesFromJson(json_content);
    } catch (const std::exception& e) {
        std::cerr << "Error loading rules: " << e.what() << std::endl;
        return false;
    }
}

bool DNSDetector::parseRulesFromJson(const std::string& json_content) {
    // Simple JSON parsing for rules
    // In a production system, use a proper JSON library like nlohmann/json
    
    rules_.clear();
    
    // Add default rules
    rules_.push_back({"DNS-001", "Detect DNS tunneling via long domains", "qname.length > 100", "high", true});
    rules_.push_back({"DNS-002", "Detect suspicious query types", "qtype in [16,255,10]", "medium", true});
    rules_.push_back({"DNS-003", "Detect DNS flooding", "queries_per_sec > 1000", "high", true});
    rules_.push_back({"DNS-004", "Detect malformed DNS packets", "malformed", "critical", true});
    rules_.push_back({"DNS-005", "Detect DGA domains", "dga_pattern", "high", true});
    rules_.push_back({"DNS-006", "Detect NXDOMAIN bursts", "nxdomain_burst", "medium", true});
    
    std::cout << "Loaded " << rules_.size() << " DNS detection rules" << std::endl;
    return true;
}

bool DNSDetector::initializeLogging(const std::string& log_file) {
    log_file_path_ = log_file;
    
    // Test if we can write to the log file
    std::ofstream test_file(log_file_path_, std::ios::app);
    if (!test_file.is_open()) {
        std::cerr << "Failed to open log file: " << log_file_path_ << std::endl;
        return false;
    }
    
    test_file.close();
    logging_enabled_ = true;
    
    // Write header
    logAlert({"SYSTEM", "INFO", "DNS NIDS Started", "", "", "", 0, TimeUtils::getCurrentTimestamp(), ""});
    
    return true;
}

std::vector<DNSAlert> DNSDetector::analyzePacket(const DNSPacket& packet) {
    std::vector<DNSAlert> alerts;
    
    // Update statistics first
    updateStatistics(packet);
    
    // Run rule-based detection
    auto rule_alerts = checkRuleBasedDetection(packet);
    alerts.insert(alerts.end(), rule_alerts.begin(), rule_alerts.end());
    
    // Run anomaly detection
    auto anomaly_alerts = checkAnomalyDetection(packet);
    alerts.insert(alerts.end(), anomaly_alerts.begin(), anomaly_alerts.end());
    
    // Log and forward alerts
    for (const auto& alert : alerts) {
        logAlert(alert);
        forwardAlert(alert);
    }
    
    return alerts;
}

void DNSDetector::updateStatistics(const DNSPacket& packet) {
    // Update global statistics
    global_stats_.query_count++;
    
    // Update query type counts
    if (!packet.questions.empty()) {
        uint16_t qtype = packet.questions[0].qtype;
        global_stats_.query_type_counts[qtype]++;
        
        // Update domain counts
        const std::string& domain = packet.questions[0].qname;
        global_stats_.domain_counts[domain]++;
    }
    
    // Check for NXDOMAIN responses
    if (packet.header.isResponse() && packet.header.getRCode() == 3) {
        global_stats_.nxdomain_count++;
    }
    
    // Update per-IP statistics
    updateIPStats(packet.source_ip, packet);
    
    // Reset statistics if needed (every hour)
    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::hours>(now - global_stats_.last_reset);
    if (duration.count() >= 1) {
        resetStatistics();
    }
}

void DNSDetector::updateIPStats(const std::string& ip, const DNSPacket& packet) {
    auto& stats = ip_stats_[ip];
    stats.total_queries++;
    
    auto now = std::chrono::steady_clock::now();
    
    // Initialize window if needed
    if (stats.window_start.time_since_epoch().count() == 0) {
        stats.window_start = now;
        stats.queries_per_window = 0;
    }
    
    // Check if we need to reset the window
    auto window_duration = std::chrono::duration_cast<std::chrono::seconds>(now - stats.window_start);
    if (window_duration.count() >= time_window_seconds_) {
        // Update baseline if enough data
        if (stats.query_history.size() >= static_cast<size_t>(baseline_window_size_)) {
            updateBaseline(ip);
        }
        
        stats.query_history.push_back(stats.queries_per_window);
        if (stats.query_history.size() > static_cast<size_t>(baseline_window_size_)) {
            stats.query_history.erase(stats.query_history.begin());
        }
        
        stats.window_start = now;
        stats.queries_per_window = 1;
    } else {
        stats.queries_per_window++;
    }
    
    // Update NXDOMAIN count
    if (packet.header.isResponse() && packet.header.getRCode() == 3) {
        stats.nxdomain_responses++;
    }
}

void DNSDetector::updateBaseline(const std::string& ip) {
    auto& stats = ip_stats_[ip];
    
    if (stats.query_history.empty()) {
        return;
    }
    
    // Calculate average query rate
    double sum = 0.0;
    for (uint32_t queries : stats.query_history) {
        sum += queries;
    }
    
    stats.baseline_rate = sum / stats.query_history.size();
    stats.baseline_established = true;
}

std::vector<DNSAlert> DNSDetector::checkRuleBasedDetection(const DNSPacket& packet) {
    std::vector<DNSAlert> alerts;
    DNSAlert alert;
    
    // Check each rule
    for (const auto& rule : rules_) {
        if (!rule.enabled) {
            continue;
        }
        
        bool triggered = false;
        
        if (rule.id == "DNS-001") {
            triggered = checkLongDomain(packet, alert);
        } else if (rule.id == "DNS-002") {
            triggered = checkSuspiciousQueryTypes(packet, alert);
        } else if (rule.id == "DNS-003") {
            triggered = checkDNSFlooding(packet, alert);
        } else if (rule.id == "DNS-004") {
            triggered = checkMalformedDNS(packet, alert);
        } else if (rule.id == "DNS-005") {
            triggered = checkDGADetection(packet, alert);
        }
        
        if (triggered) {
            alerts.push_back(alert);
        }
    }
    
    return alerts;
}

std::vector<DNSAlert> DNSDetector::checkAnomalyDetection(const DNSPacket& packet) {
    std::vector<DNSAlert> alerts;
    DNSAlert alert;
    
    if (checkVolumeSpike(packet, alert)) {
        alerts.push_back(alert);
    }
    
    if (checkNXDomainBurst(packet, alert)) {
        alerts.push_back(alert);
    }
    
    if (checkUnusualQueryPattern(packet, alert)) {
        alerts.push_back(alert);
    }
    
    return alerts;
}

bool DNSDetector::checkMalformedDNS(const DNSPacket& packet, DNSAlert& alert) {
    // Check for various malformations
    bool malformed = false;
    std::string details;
    
    // Check header sanity
    if (packet.header.qdcount == 0 && packet.header.ancount == 0 && 
        packet.header.nscount == 0 && packet.header.arcount == 0) {
        malformed = true;
        details += "Empty DNS packet; ";
    }
    
    // Check question section
    if (packet.header.qdcount > 0 && packet.questions.empty()) {
        malformed = true;
        details += "Missing question section; ";
    }
    
    // Check for invalid domain names
    for (const auto& question : packet.questions) {
        if (question.qname.empty() || question.qname.length() > 253) {
            malformed = true;
            details += "Invalid domain name length; ";
            break;
        }
    }
    
    if (malformed) {
        alert.rule_id = "DNS-004";
        alert.severity = "critical";
        alert.description = "Malformed DNS packet detected";
        alert.source_ip = packet.source_ip;
        alert.dest_ip = packet.dest_ip;
        alert.query_name = packet.questions.empty() ? "" : packet.questions[0].qname;
        alert.query_type = packet.questions.empty() ? 0 : packet.questions[0].qtype;
        alert.timestamp = packet.timestamp;
        alert.details = details;
    }
    
    return malformed;
}

bool DNSDetector::checkLongDomain(const DNSPacket& packet, DNSAlert& alert) {
    if (packet.questions.empty()) {
        return false;
    }
    
    const std::string& domain = packet.questions[0].qname;
    if (domain.length() > MAX_DOMAIN_LENGTH) {
        alert.rule_id = "DNS-001";
        alert.severity = "high";
        alert.description = "Long domain name detected (possible DNS tunneling)";
        alert.source_ip = packet.source_ip;
        alert.dest_ip = packet.dest_ip;
        alert.query_name = domain;
        alert.query_type = packet.questions[0].qtype;
        alert.timestamp = packet.timestamp;
        alert.details = "Domain length: " + std::to_string(domain.length());
        return true;
    }
    
    return false;
}

bool DNSDetector::checkSuspiciousQueryTypes(const DNSPacket& packet, DNSAlert& alert) {
    if (packet.questions.empty()) {
        return false;
    }
    
    uint16_t qtype = packet.questions[0].qtype;
    if (isRareQueryType(qtype)) {
        alert.rule_id = "DNS-002";
        alert.severity = "medium";
        alert.description = "Suspicious query type detected";
        alert.source_ip = packet.source_ip;
        alert.dest_ip = packet.dest_ip;
        alert.query_name = packet.questions[0].qname;
        alert.query_type = qtype;
        alert.timestamp = packet.timestamp;
        alert.details = "Query type: " + std::to_string(qtype);
        return true;
    }
    
    return false;
}

bool DNSDetector::checkDNSFlooding(const DNSPacket& packet, DNSAlert& alert) {
    const std::string& ip = packet.source_ip;
    auto it = ip_stats_.find(ip);
    
    if (it != ip_stats_.end()) {
        uint32_t queries_per_sec = it->second.queries_per_window / 
                                   std::max(1, time_window_seconds_);
        
        if (queries_per_sec > MAX_QUERIES_PER_SECOND) {
            alert.rule_id = "DNS-003";
            alert.severity = "high";
            alert.description = "DNS flooding detected";
            alert.source_ip = packet.source_ip;
            alert.dest_ip = packet.dest_ip;
            alert.query_name = packet.questions.empty() ? "" : packet.questions[0].qname;
            alert.query_type = packet.questions.empty() ? 0 : packet.questions[0].qtype;
            alert.timestamp = packet.timestamp;
            alert.details = "Queries per second: " + std::to_string(queries_per_sec);
            return true;
        }
    }
    
    return false;
}

bool DNSDetector::checkDGADetection(const DNSPacket& packet, DNSAlert& alert) {
    if (packet.questions.empty()) {
        return false;
    }
    
    const std::string& domain = packet.questions[0].qname;
    if (isDGA(domain)) {
        alert.rule_id = "DNS-005";
        alert.severity = "high";
        alert.description = "DGA domain detected";
        alert.source_ip = packet.source_ip;
        alert.dest_ip = packet.dest_ip;
        alert.query_name = domain;
        alert.query_type = packet.questions[0].qtype;
        alert.timestamp = packet.timestamp;
        alert.details = "Entropy: " + std::to_string(calculateEntropy(domain));
        return true;
    }
    
    return false;
}

bool DNSDetector::checkDNSTunneling(const DNSPacket& packet, DNSAlert& alert) {
    // This would implement more sophisticated tunneling detection
    // For now, it's covered by long domain detection
    return false;
}

bool DNSDetector::checkVolumeSpike(const DNSPacket& packet, DNSAlert& alert) {
    const std::string& ip = packet.source_ip;
    auto it = ip_stats_.find(ip);
    
    if (it != ip_stats_.end() && it->second.baseline_established) {
        double current_rate = it->second.queries_per_window;
        double baseline = it->second.baseline_rate;
        
        if (current_rate > baseline * anomaly_threshold_) {
            alert.rule_id = "ANOMALY-001";
            alert.severity = "medium";
            alert.description = "Volume spike detected";
            alert.source_ip = packet.source_ip;
            alert.dest_ip = packet.dest_ip;
            alert.query_name = packet.questions.empty() ? "" : packet.questions[0].qname;
            alert.query_type = packet.questions.empty() ? 0 : packet.questions[0].qtype;
            alert.timestamp = packet.timestamp;
            alert.details = "Current: " + std::to_string(current_rate) + 
                           ", Baseline: " + std::to_string(baseline);
            return true;
        }
    }
    
    return false;
}

bool DNSDetector::checkNXDomainBurst(const DNSPacket& packet, DNSAlert& alert) {
    if (!packet.header.isResponse() || packet.header.getRCode() != 3) {
        return false;
    }
    
    const std::string& ip = packet.source_ip;
    auto it = ip_stats_.find(ip);
    
    if (it != ip_stats_.end()) {
        // Check if NXDOMAIN rate is too high
        double nxdomain_rate = static_cast<double>(it->second.nxdomain_responses) / 
                              std::max(1u, it->second.queries_per_window);
        
        if (nxdomain_rate > 0.5 && it->second.queries_per_window > 10) {
            alert.rule_id = "ANOMALY-002";
            alert.severity = "medium";
            alert.description = "NXDOMAIN burst detected";
            alert.source_ip = packet.source_ip;
            alert.dest_ip = packet.dest_ip;
            alert.query_name = packet.questions.empty() ? "" : packet.questions[0].qname;
            alert.query_type = packet.questions.empty() ? 0 : packet.questions[0].qtype;
            alert.timestamp = packet.timestamp;
            alert.details = "NXDOMAIN rate: " + std::to_string(nxdomain_rate * 100) + "%";
            return true;
        }
    }
    
    return false;
}

bool DNSDetector::checkUnusualQueryPattern(const DNSPacket& packet, DNSAlert& alert) {
    // This could implement more sophisticated pattern analysis
    return false;
}

void DNSDetector::logAlert(const DNSAlert& alert) {
    if (!logging_enabled_) {
        return;
    }
    
    std::ofstream log_file(log_file_path_, std::ios::app);
    if (!log_file.is_open()) {
        return;
    }
    
    std::string timestamp = TimeUtils::formatTimestamp(alert.timestamp);
    
    log_file << timestamp << " | "
             << alert.rule_id << " | "
             << alert.severity << " | "
             << alert.description << " | "
             << alert.source_ip << " | "
             << alert.dest_ip << " | "
             << alert.query_name << " | "
             << alert.query_type << " | "
             << alert.details << std::endl;
    
    log_file.close();
}

void DNSDetector::forwardAlert(const DNSAlert& alert) {
    // Forward to stdout for now (could be extended to send to dashboard)
    std::cout << "[ALERT] " << alert.severity << " - " << alert.description 
              << " from " << alert.source_ip << " querying " << alert.query_name 
              << std::endl;
}

bool DNSDetector::isDGA(const std::string& domain) const {
    if (domain.length() < MIN_DGA_DOMAIN_LENGTH) {
        return false;
    }
    
    // Calculate entropy
    double entropy = calculateEntropy(domain);
    if (entropy > DGA_ENTROPY_THRESHOLD) {
        return true;
    }
    
    // Check for suspicious patterns
    return containsSuspiciousPatterns(domain);
}

double DNSDetector::calculateEntropy(const std::string& str) const {
    if (str.empty()) {
        return 0.0;
    }
    
    std::unordered_map<char, int> freq;
    for (char c : str) {
        freq[c]++;
    }
    
    double entropy = 0.0;
    double len = static_cast<double>(str.length());
    
    for (const auto& pair : freq) {
        double p = static_cast<double>(pair.second) / len;
        entropy -= p * std::log2(p);
    }
    
    return entropy;
}

bool DNSDetector::containsSuspiciousPatterns(const std::string& domain) const {
    // Check for patterns common in DGA domains
    std::regex patterns[] = {
        std::regex(R"([0-9]{5,})"),  // Long sequences of digits
        std::regex(R"([a-z]{20,})"), // Very long character sequences
        std::regex(R"(^[a-z0-9]{32,}\.)")  // Very long subdomains
    };
    
    for (const auto& pattern : patterns) {
        if (std::regex_search(domain, pattern)) {
            return true;
        }
    }
    
    return false;
}

bool DNSDetector::isRareQueryType(uint16_t qtype) const {
    return std::find(RARE_QUERY_TYPES.begin(), RARE_QUERY_TYPES.end(), qtype) != 
           RARE_QUERY_TYPES.end();
}

void DNSDetector::printStatistics() const {
    std::cout << "\n=== DNS Detection Statistics ===" << std::endl;
    std::cout << "Total queries processed: " << global_stats_.query_count << std::endl;
    std::cout << "NXDOMAIN responses: " << global_stats_.nxdomain_count << std::endl;
    std::cout << "Unique IPs monitored: " << ip_stats_.size() << std::endl;
    
    std::cout << "\nQuery type distribution:" << std::endl;
    for (const auto& pair : global_stats_.query_type_counts) {
        std::cout << "  Type " << pair.first << ": " << pair.second << " queries" << std::endl;
    }
}

void DNSDetector::resetStatistics() {
    global_stats_.query_count = 0;
    global_stats_.nxdomain_count = 0;
    global_stats_.large_response_count = 0;
    global_stats_.last_reset = std::chrono::steady_clock::now();
    global_stats_.query_type_counts.clear();
    global_stats_.domain_counts.clear();
    
    // Reset IP statistics but keep baseline data
    for (auto& pair : ip_stats_) {
        pair.second.nxdomain_responses = 0;
        pair.second.queries_per_window = 0;
        pair.second.window_start = std::chrono::steady_clock::now();
    }
}

std::string DNSDetector::getCurrentTimestamp() const {
    return TimeUtils::getCurrentTimeString();
}
