#include "utils.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <cmath>
#include <chrono>
#include <cstring>
#include <cctype>
#include <regex>
#include <map>
#include <unordered_map>

#ifdef _WIN32
#include <winsock2.h>
#include <direct.h>
#define mkdir(path, mode) _mkdir(path)
#else
#include <arpa/inet.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

// Logger implementation
Logger::Logger(const std::string& log_file, LogLevel min_level)
    : min_level_(min_level), console_output_(true), timestamp_enabled_(true) {
    
    if (!log_file.empty()) {
        log_file_.open(log_file, std::ios::app);
        if (!log_file_.is_open()) {
            std::cerr << "Warning: Could not open log file: " << log_file << std::endl;
        }
    }
}

Logger::~Logger() {
    if (log_file_.is_open()) {
        log_file_.close();
    }
}

void Logger::log(LogLevel level, const std::string& message) {
    if (level < min_level_) {
        return;
    }
    
    std::string log_message;
    
    if (timestamp_enabled_) {
        log_message += "[" + getCurrentTimestamp() + "] ";
    }
    
    log_message += "[" + levelToString(level) + "] " + message;
    
    if (console_output_) {
        std::cout << log_message << std::endl;
    }
    
    if (log_file_.is_open()) {
        log_file_ << log_message << std::endl;
        log_file_.flush();
    }
}

std::string Logger::levelToString(LogLevel level) const {
    switch (level) {
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO: return "INFO";
        case LogLevel::WARNING: return "WARNING";
        case LogLevel::ERROR: return "ERROR";
        case LogLevel::CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

std::string Logger::getCurrentTimestamp() const {
    return TimeUtils::getCurrentTimeString();
}

// Network utility functions
namespace NetworkUtils {
    uint16_t networkToHost16(uint16_t network_value) {
        return ntohs(network_value);
    }
    
    uint32_t networkToHost32(uint32_t network_value) {
        return ntohl(network_value);
    }
    
    uint16_t hostToNetwork16(uint16_t host_value) {
        return htons(host_value);
    }
    
    uint32_t hostToNetwork32(uint32_t host_value) {
        return htonl(host_value);
    }
    
    std::string formatIPv4Address(uint32_t ip_addr) {
        struct in_addr addr;
        addr.s_addr = ip_addr;
        return std::string(inet_ntoa(addr));
    }
    
    std::string formatIPv6Address(const uint8_t* ip_addr) {
        char buffer[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, ip_addr, buffer, INET6_ADDRSTRLEN);
        return std::string(buffer);
    }
    
    bool parseIPv4Address(const std::string& ip_str, uint32_t& ip_addr) {
        struct in_addr addr;
        if (inet_aton(ip_str.c_str(), &addr) != 0) {
            ip_addr = addr.s_addr;
            return true;
        }
        return false;
    }
    
    std::string formatMACAddress(const uint8_t* mac_addr) {
        std::ostringstream oss;
        for (int i = 0; i < 6; ++i) {
            if (i > 0) oss << ":";
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mac_addr[i]);
        }
        return oss.str();
    }
    
    std::string getServiceName(uint16_t port, const std::string& protocol) {
        // Common service mappings
        static const std::map<uint16_t, std::string> services = {
            {20, "ftp-data"}, {21, "ftp"}, {22, "ssh"}, {23, "telnet"},
            {25, "smtp"}, {53, "dns"}, {67, "dhcp"}, {68, "dhcp"},
            {80, "http"}, {110, "pop3"}, {143, "imap"}, {443, "https"},
            {993, "imaps"}, {995, "pop3s"}
        };
        
        auto it = services.find(port);
        if (it != services.end()) {
            return it->second;
        }
        
        return "unknown";
    }
    
    bool isWellKnownPort(uint16_t port) {
        return port < 1024;
    }
}

// String utility functions
namespace StringUtils {
    std::string formatDomainName(const std::string& raw_domain) {
        std::string formatted = raw_domain;
        
        // Remove trailing dot if present
        if (!formatted.empty() && formatted.back() == '.') {
            formatted.pop_back();
        }
        
        return toLower(formatted);
    }
    
    bool isValidDomainName(const std::string& domain) {
        if (domain.empty() || domain.length() > 253) {
            return false;
        }
        
        // Check for invalid characters
        std::regex valid_pattern(R"(^[a-zA-Z0-9.-]+$)");
        if (!std::regex_match(domain, valid_pattern)) {
            return false;
        }
        
        // Check labels
        auto labels = splitDomainLabels(domain);
        for (const auto& label : labels) {
            if (label.empty() || label.length() > 63) {
                return false;
            }
            
            // Label cannot start or end with hyphen
            if (label.front() == '-' || label.back() == '-') {
                return false;
            }
        }
        
        return true;
    }
    
    std::vector<std::string> splitDomainLabels(const std::string& domain) {
        return split(domain, '.');
    }
    
    std::string normalizeDomainName(const std::string& domain) {
        return formatDomainName(domain);
    }
    
    std::string toLower(const std::string& str) {
        std::string result = str;
        std::transform(result.begin(), result.end(), result.begin(), ::tolower);
        return result;
    }
    
    std::string toUpper(const std::string& str) {
        std::string result = str;
        std::transform(result.begin(), result.end(), result.begin(), ::toupper);
        return result;
    }
    
    std::string trim(const std::string& str) {
        size_t first = str.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) {
            return "";
        }
        
        size_t last = str.find_last_not_of(" \t\r\n");
        return str.substr(first, last - first + 1);
    }
    
    std::vector<std::string> split(const std::string& str, char delimiter) {
        std::vector<std::string> tokens;
        std::stringstream ss(str);
        std::string token;
        
        while (std::getline(ss, token, delimiter)) {
            tokens.push_back(token);
        }
        
        return tokens;
    }
    
    std::string join(const std::vector<std::string>& strings, const std::string& delimiter) {
        if (strings.empty()) {
            return "";
        }
        
        std::ostringstream result;
        for (size_t i = 0; i < strings.size(); ++i) {
            if (i > 0) {
                result << delimiter;
            }
            result << strings[i];
        }
        
        return result.str();
    }
    
    std::string hexEncode(const uint8_t* data, size_t length) {
        std::ostringstream oss;
        for (size_t i = 0; i < length; ++i) {
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
        }
        return oss.str();
    }
    
    std::vector<uint8_t> hexDecode(const std::string& hex_string) {
        std::vector<uint8_t> result;
        
        for (size_t i = 0; i < hex_string.length(); i += 2) {
            if (i + 1 < hex_string.length()) {
                std::string byte_str = hex_string.substr(i, 2);
                uint8_t byte = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
                result.push_back(byte);
            }
        }
        
        return result;
    }
    
    std::string base64Encode(const uint8_t* data, size_t length) {
        // Simple base64 implementation
        const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string result;
        
        for (size_t i = 0; i < length; i += 3) {
            uint32_t value = data[i] << 16;
            if (i + 1 < length) value |= data[i + 1] << 8;
            if (i + 2 < length) value |= data[i + 2];
            
            result += chars[(value >> 18) & 0x3F];
            result += chars[(value >> 12) & 0x3F];
            result += (i + 1 < length) ? chars[(value >> 6) & 0x3F] : '=';
            result += (i + 2 < length) ? chars[value & 0x3F] : '=';
        }
        
        return result;
    }
    
    std::vector<uint8_t> base64Decode(const std::string& base64_string) {
        // Simple base64 decode implementation
        std::vector<uint8_t> result;
        // Implementation omitted for brevity
        return result;
    }
    
    bool containsPattern(const std::string& text, const std::string& pattern) {
        return text.find(pattern) != std::string::npos;
    }
    
    bool matchesWildcard(const std::string& text, const std::string& pattern) {
        // Simple wildcard matching (* and ?)
        std::regex regex_pattern(pattern);
        // Convert wildcard to regex
        std::string regex_str = pattern;
        std::replace(regex_str.begin(), regex_str.end(), '*', '.');
        regex_str += "*";
        
        try {
            std::regex regex(regex_str);
            return std::regex_match(text, regex);
        } catch (const std::exception&) {
            return false;
        }
    }
    
    double calculateEntropy(const std::string& text) {
        if (text.empty()) {
            return 0.0;
        }
        
        std::unordered_map<char, int> freq;
        for (char c : text) {
            freq[c]++;
        }
        
        double entropy = 0.0;
        double len = static_cast<double>(text.length());
        
        for (const auto& pair : freq) {
            double p = static_cast<double>(pair.second) / len;
            entropy -= p * std::log2(p);
        }
        
        return entropy;
    }
}

// Time utility functions
namespace TimeUtils {
    uint64_t getCurrentTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto duration = now.time_since_epoch();
        return std::chrono::duration_cast<std::chrono::seconds>(duration).count();
    }
    
    uint64_t getTimestampMs() {
        auto now = std::chrono::system_clock::now();
        auto duration = now.time_since_epoch();
        return std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
    }
    
    std::string formatTimestamp(uint64_t timestamp, const std::string& format) {
        std::time_t time = static_cast<std::time_t>(timestamp);
        std::tm* tm_info = std::localtime(&time);
        
        std::ostringstream oss;
        oss << std::put_time(tm_info, format.c_str());
        return oss.str();
    }
    
    std::string getCurrentTimeString(const std::string& format) {
        return formatTimestamp(getCurrentTimestamp(), format);
    }
    
    uint64_t timeDifferenceMs(uint64_t start, uint64_t end) {
        return (end > start) ? (end - start) : 0;
    }
    
    bool isWithinTimeWindow(uint64_t timestamp, uint64_t window_start, uint64_t window_size_ms) {
        return (timestamp >= window_start) && (timestamp <= window_start + window_size_ms);
    }
}

// File utility functions
namespace FileUtils {
    bool fileExists(const std::string& filename) {
        std::ifstream file(filename);
        return file.good();
    }
    
    bool createDirectory(const std::string& dir_path) {
        return mkdir(dir_path.c_str(), 0755) == 0;
    }
    
    bool createDirectoryRecursive(const std::string& dir_path) {
        size_t pos = 0;
        std::string delimiter = "/";
        
        #ifdef _WIN32
        delimiter = "\\";
        #endif
        
        while ((pos = dir_path.find(delimiter, pos)) != std::string::npos) {
            std::string subdir = dir_path.substr(0, pos);
            if (!subdir.empty() && !fileExists(subdir)) {
                if (!createDirectory(subdir)) {
                    return false;
                }
            }
            pos += delimiter.length();
        }
        
        return createDirectory(dir_path);
    }
    
    std::string getFileExtension(const std::string& filename) {
        size_t dot_pos = filename.find_last_of('.');
        if (dot_pos != std::string::npos) {
            return filename.substr(dot_pos + 1);
        }
        return "";
    }
    
    std::string getBasename(const std::string& filepath) {
        size_t slash_pos = filepath.find_last_of("/\\");
        if (slash_pos != std::string::npos) {
            return filepath.substr(slash_pos + 1);
        }
        return filepath;
    }
    
    std::string getDirname(const std::string& filepath) {
        size_t slash_pos = filepath.find_last_of("/\\");
        if (slash_pos != std::string::npos) {
            return filepath.substr(0, slash_pos);
        }
        return ".";
    }
    
    std::string readTextFile(const std::string& filename) {
        std::ifstream file(filename);
        if (!file.is_open()) {
            return "";
        }
        
        std::ostringstream content;
        content << file.rdbuf();
        return content.str();
    }
    
    bool writeTextFile(const std::string& filename, const std::string& content) {
        std::ofstream file(filename);
        if (!file.is_open()) {
            return false;
        }
        
        file << content;
        return file.good();
    }
    
    bool appendToFile(const std::string& filename, const std::string& content) {
        std::ofstream file(filename, std::ios::app);
        if (!file.is_open()) {
            return false;
        }
        
        file << content;
        return file.good();
    }
    
    size_t getFileSize(const std::string& filename) {
        std::ifstream file(filename, std::ios::binary | std::ios::ate);
        if (file.is_open()) {
            return static_cast<size_t>(file.tellg());
        }
        return 0;
    }
    
    uint64_t getFileModTime(const std::string& filename) {
        struct stat file_stat;
        if (stat(filename.c_str(), &file_stat) == 0) {
            return static_cast<uint64_t>(file_stat.st_mtime);
        }
        return 0;
    }
}

// JSON utility functions
namespace JsonUtils {
    std::string escapeJsonString(const std::string& str) {
        std::string escaped;
        for (char c : str) {
            switch (c) {
                case '"': escaped += "\\\""; break;
                case '\\': escaped += "\\\\"; break;
                case '\b': escaped += "\\b"; break;
                case '\f': escaped += "\\f"; break;
                case '\n': escaped += "\\n"; break;
                case '\r': escaped += "\\r"; break;
                case '\t': escaped += "\\t"; break;
                default: escaped += c; break;
            }
        }
        return escaped;
    }
    
    std::string formatJsonValue(const std::string& value, bool is_string) {
        if (is_string) {
            return "\"" + escapeJsonString(value) + "\"";
        }
        return value;
    }
    
    std::string formatJsonObject(const std::vector<std::pair<std::string, std::string>>& fields) {
        std::ostringstream json;
        json << "{";
        
        for (size_t i = 0; i < fields.size(); ++i) {
            if (i > 0) json << ",";
            json << "\"" << escapeJsonString(fields[i].first) << "\":";
            json << fields[i].second;
        }
        
        json << "}";
        return json.str();
    }
    
    std::string formatJsonArray(const std::vector<std::string>& values) {
        std::ostringstream json;
        json << "[";
        
        for (size_t i = 0; i < values.size(); ++i) {
            if (i > 0) json << ",";
            json << values[i];
        }
        
        json << "]";
        return json.str();
    }
    
    bool isValidJson(const std::string& json_str) {
        // Simple JSON validation - check for balanced braces
        int brace_count = 0;
        bool in_string = false;
        bool escaped = false;
        
        for (char c : json_str) {
            if (escaped) {
                escaped = false;
                continue;
            }
            
            if (c == '\\') {
                escaped = true;
                continue;
            }
            
            if (c == '"') {
                in_string = !in_string;
                continue;
            }
            
            if (!in_string) {
                if (c == '{' || c == '[') {
                    brace_count++;
                } else if (c == '}' || c == ']') {
                    brace_count--;
                }
            }
        }
        
        return brace_count == 0 && !in_string;
    }
    
    std::string extractJsonField(const std::string& json_str, const std::string& field_name) {
        // Simple field extraction - not a complete JSON parser
        std::string search_pattern = "\"" + field_name + "\"";
        size_t pos = json_str.find(search_pattern);
        
        if (pos == std::string::npos) {
            return "";
        }
        
        pos = json_str.find(":", pos);
        if (pos == std::string::npos) {
            return "";
        }
        
        pos++; // Skip ':'
        while (pos < json_str.length() && std::isspace(json_str[pos])) {
            pos++;
        }
        
        if (pos >= json_str.length()) {
            return "";
        }
        
        size_t start = pos;
        size_t end = pos;
        
        if (json_str[pos] == '"') {
            // String value
            start = pos + 1;
            end = json_str.find('"', start);
        } else {
            // Numeric or boolean value
            while (end < json_str.length() && json_str[end] != ',' && json_str[end] != '}') {
                end++;
            }
        }
        
        if (end != std::string::npos && end > start) {
            return json_str.substr(start, end - start);
        }
        
        return "";
    }
}

// Memory utility functions
namespace MemoryUtils {
    void secureClear(void* ptr, size_t size) {
        if (ptr && size > 0) {
            std::memset(ptr, 0, size);
        }
    }
    
    bool isValidPointer(const void* ptr, size_t size) {
        return ptr != nullptr && size > 0;
    }
    
    std::string hexDump(const void* data, size_t size, size_t bytes_per_line) {
        const uint8_t* bytes = static_cast<const uint8_t*>(data);
        std::ostringstream dump;
        
        for (size_t i = 0; i < size; i += bytes_per_line) {
            // Address
            dump << std::hex << std::setw(8) << std::setfill('0') << i << ": ";
            
            // Hex bytes
            for (size_t j = 0; j < bytes_per_line && i + j < size; ++j) {
                dump << std::hex << std::setw(2) << std::setfill('0') 
                     << static_cast<int>(bytes[i + j]) << " ";
            }
            
            // ASCII representation
            dump << " |";
            for (size_t j = 0; j < bytes_per_line && i + j < size; ++j) {
                char c = bytes[i + j];
                dump << (std::isprint(c) ? c : '.');
            }
            dump << "|\n";
        }
        
        return dump.str();
    }
    
    void printHexDump(const void* data, size_t size, const std::string& title) {
        if (!title.empty()) {
            std::cout << title << std::endl;
            std::cout << std::string(title.length(), '=') << std::endl;
        }
        
        std::cout << hexDump(data, size) << std::endl;
    }
}

// ConfigManager implementation
ConfigManager::ConfigManager(const std::string& config_file)
    : config_file_(config_file) {
    
    if (!config_file_.empty()) {
        loadFromFile(config_file_);
    }
}

ConfigManager::~ConfigManager() {
    // Destructor
}

bool ConfigManager::loadFromFile(const std::string& config_file) {
    config_file_ = config_file;
    
    std::ifstream file(config_file);
    if (!file.is_open()) {
        return false;
    }
    
    std::string line;
    while (std::getline(file, line)) {
        line = trim(line);
        
        // Skip empty lines and comments
        if (line.empty() || line[0] == '#' || line[0] == ';') {
            continue;
        }
        
        auto key_value = parseLine(line);
        if (!key_value.first.empty()) {
            config_data_[key_value.first] = key_value.second;
        }
    }
    
    return true;
}

bool ConfigManager::loadFromString(const std::string& config_content) {
    std::istringstream content(config_content);
    std::string line;
    
    while (std::getline(content, line)) {
        line = trim(line);
        
        if (line.empty() || line[0] == '#' || line[0] == ';') {
            continue;
        }
        
        auto key_value = parseLine(line);
        if (!key_value.first.empty()) {
            config_data_[key_value.first] = key_value.second;
        }
    }
    
    return true;
}

std::string ConfigManager::getString(const std::string& key, const std::string& default_value) const {
    auto it = config_data_.find(key);
    return (it != config_data_.end()) ? it->second : default_value;
}

int ConfigManager::getInt(const std::string& key, int default_value) const {
    auto it = config_data_.find(key);
    if (it != config_data_.end()) {
        try {
            return std::stoi(it->second);
        } catch (const std::exception&) {
            // Return default on conversion error
        }
    }
    return default_value;
}

double ConfigManager::getDouble(const std::string& key, double default_value) const {
    auto it = config_data_.find(key);
    if (it != config_data_.end()) {
        try {
            return std::stod(it->second);
        } catch (const std::exception&) {
            // Return default on conversion error
        }
    }
    return default_value;
}

bool ConfigManager::getBool(const std::string& key, bool default_value) const {
    auto it = config_data_.find(key);
    if (it != config_data_.end()) {
        std::string value = StringUtils::toLower(it->second);
        return (value == "true" || value == "yes" || value == "1");
    }
    return default_value;
}

void ConfigManager::setString(const std::string& key, const std::string& value) {
    config_data_[key] = value;
}

void ConfigManager::setInt(const std::string& key, int value) {
    config_data_[key] = std::to_string(value);
}

void ConfigManager::setDouble(const std::string& key, double value) {
    config_data_[key] = std::to_string(value);
}

void ConfigManager::setBool(const std::string& key, bool value) {
    config_data_[key] = value ? "true" : "false";
}

bool ConfigManager::saveToFile(const std::string& config_file) const {
    std::string filename = config_file.empty() ? config_file_ : config_file;
    if (filename.empty()) {
        return false;
    }
    
    std::ofstream file(filename);
    if (!file.is_open()) {
        return false;
    }
    
    for (const auto& pair : config_data_) {
        file << pair.first << "=" << pair.second << std::endl;
    }
    
    return true;
}

bool ConfigManager::hasKey(const std::string& key) const {
    return config_data_.find(key) != config_data_.end();
}

std::vector<std::string> ConfigManager::getKeys() const {
    std::vector<std::string> keys;
    for (const auto& pair : config_data_) {
        keys.push_back(pair.first);
    }
    return keys;
}

void ConfigManager::clear() {
    config_data_.clear();
}

std::string ConfigManager::trim(const std::string& str) const {
    return StringUtils::trim(str);
}

std::pair<std::string, std::string> ConfigManager::parseLine(const std::string& line) const {
    size_t equals_pos = line.find('=');
    if (equals_pos != std::string::npos) {
        std::string key = trim(line.substr(0, equals_pos));
        std::string value = trim(line.substr(equals_pos + 1));
        return std::make_pair(key, value);
    }
    
    return std::make_pair("", "");
}
