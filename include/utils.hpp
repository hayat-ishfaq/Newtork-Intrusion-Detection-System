#ifndef UTILS_HPP
#define UTILS_HPP

#include <string>
#include <fstream>
#include <memory>
#include <chrono>
#include <map>
#include <vector>
#include <cstdint>
#include <memory>
#include <chrono>

// Logging levels
enum class LogLevel {
    DEBUG = 0,
    INFO = 1,
    WARNING = 2,
    ERROR = 3,
    CRITICAL = 4
};

// Logger class for centralized logging
class Logger {
public:
    Logger(const std::string& log_file, LogLevel min_level = LogLevel::INFO);
    ~Logger();
    
    // Logging methods
    void log(LogLevel level, const std::string& message);
    void debug(const std::string& message) { log(LogLevel::DEBUG, message); }
    void info(const std::string& message) { log(LogLevel::INFO, message); }
    void warning(const std::string& message) { log(LogLevel::WARNING, message); }
    void error(const std::string& message) { log(LogLevel::ERROR, message); }
    void critical(const std::string& message) { log(LogLevel::CRITICAL, message); }
    
    // Configuration
    void setMinLevel(LogLevel level) { min_level_ = level; }
    void enableConsoleOutput(bool enable) { console_output_ = enable; }
    void enableTimestamp(bool enable) { timestamp_enabled_ = enable; }
    
    // File operations
    bool isOpen() const { return log_file_.is_open(); }
    void flush() { log_file_.flush(); }
    
private:
    std::ofstream log_file_;
    LogLevel min_level_;
    bool console_output_;
    bool timestamp_enabled_;
    
    std::string levelToString(LogLevel level) const;
    std::string getCurrentTimestamp() const;
};

// Network utility functions
namespace NetworkUtils {
    // Byte order conversions
    uint16_t networkToHost16(uint16_t network_value);
    uint32_t networkToHost32(uint32_t network_value);
    uint16_t hostToNetwork16(uint16_t host_value);
    uint32_t hostToNetwork32(uint32_t host_value);
    
    // IP address formatting
    std::string formatIPv4Address(uint32_t ip_addr);
    std::string formatIPv6Address(const uint8_t* ip_addr);
    bool parseIPv4Address(const std::string& ip_str, uint32_t& ip_addr);
    
    // MAC address formatting
    std::string formatMACAddress(const uint8_t* mac_addr);
    
    // Port utilities
    std::string getServiceName(uint16_t port, const std::string& protocol);
    bool isWellKnownPort(uint16_t port);
}

// String utility functions
namespace StringUtils {
    // Domain name utilities
    std::string formatDomainName(const std::string& raw_domain);
    bool isValidDomainName(const std::string& domain);
    std::vector<std::string> splitDomainLabels(const std::string& domain);
    std::string normalizeDomainName(const std::string& domain);
    
    // String manipulation
    std::string toLower(const std::string& str);
    std::string toUpper(const std::string& str);
    std::string trim(const std::string& str);
    std::vector<std::string> split(const std::string& str, char delimiter);
    std::string join(const std::vector<std::string>& strings, const std::string& delimiter);
    
    // Encoding/Decoding
    std::string hexEncode(const uint8_t* data, size_t length);
    std::vector<uint8_t> hexDecode(const std::string& hex_string);
    std::string base64Encode(const uint8_t* data, size_t length);
    std::vector<uint8_t> base64Decode(const std::string& base64_string);
    
    // Pattern matching
    bool containsPattern(const std::string& text, const std::string& pattern);
    bool matchesWildcard(const std::string& text, const std::string& pattern);
    double calculateEntropy(const std::string& text);
}

// Time utility functions
namespace TimeUtils {
    // Timestamp functions
    uint64_t getCurrentTimestamp();
    uint64_t getTimestampMs();
    std::string formatTimestamp(uint64_t timestamp, const std::string& format = "%Y-%m-%d %H:%M:%S");
    std::string getCurrentTimeString(const std::string& format = "%Y-%m-%d %H:%M:%S");
    
    // Time calculations
    uint64_t timeDifferenceMs(uint64_t start, uint64_t end);
    bool isWithinTimeWindow(uint64_t timestamp, uint64_t window_start, uint64_t window_size_ms);
}

// File utility functions
namespace FileUtils {
    // File operations
    bool fileExists(const std::string& filename);
    bool createDirectory(const std::string& dir_path);
    bool createDirectoryRecursive(const std::string& dir_path);
    std::string getFileExtension(const std::string& filename);
    std::string getBasename(const std::string& filepath);
    std::string getDirname(const std::string& filepath);
    
    // File I/O
    std::string readTextFile(const std::string& filename);
    bool writeTextFile(const std::string& filename, const std::string& content);
    bool appendToFile(const std::string& filename, const std::string& content);
    
    // File size and info
    size_t getFileSize(const std::string& filename);
    uint64_t getFileModTime(const std::string& filename);
}

// JSON utility functions
namespace JsonUtils {
    // JSON formatting helpers
    std::string escapeJsonString(const std::string& str);
    std::string formatJsonValue(const std::string& value, bool is_string = true);
    std::string formatJsonObject(const std::vector<std::pair<std::string, std::string>>& fields);
    std::string formatJsonArray(const std::vector<std::string>& values);
    
    // JSON parsing helpers (basic)
    bool isValidJson(const std::string& json_str);
    std::string extractJsonField(const std::string& json_str, const std::string& field_name);
}

// Memory utility functions
namespace MemoryUtils {
    // Safe memory operations
    void secureClear(void* ptr, size_t size);
    bool isValidPointer(const void* ptr, size_t size);
    
    // Memory dump utilities
    std::string hexDump(const void* data, size_t size, size_t bytes_per_line = 16);
    void printHexDump(const void* data, size_t size, const std::string& title = "");
}

// Configuration management
class ConfigManager {
public:
    ConfigManager(const std::string& config_file = "");
    ~ConfigManager();
    
    // Configuration loading
    bool loadFromFile(const std::string& config_file);
    bool loadFromString(const std::string& config_content);
    
    // Value getters
    std::string getString(const std::string& key, const std::string& default_value = "") const;
    int getInt(const std::string& key, int default_value = 0) const;
    double getDouble(const std::string& key, double default_value = 0.0) const;
    bool getBool(const std::string& key, bool default_value = false) const;
    
    // Value setters
    void setString(const std::string& key, const std::string& value);
    void setInt(const std::string& key, int value);
    void setDouble(const std::string& key, double value);
    void setBool(const std::string& key, bool value);
    
    // Configuration persistence
    bool saveToFile(const std::string& config_file = "") const;
    
    // Utility
    bool hasKey(const std::string& key) const;
    std::vector<std::string> getKeys() const;
    void clear();
    
private:
    std::string config_file_;
    std::map<std::string, std::string> config_data_;
    
    std::string trim(const std::string& str) const;
    std::pair<std::string, std::string> parseLine(const std::string& line) const;
};

#endif // UTILS_HPP
