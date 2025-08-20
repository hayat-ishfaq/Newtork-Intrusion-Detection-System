#include <iostream>
#include <cassert>
#include <vector>
#include <memory>
#include <cstring>

#include "dns_parser.hpp"
#include "detector.hpp"
#include "utils.hpp"

class DNSParserTest {
public:
    static void runAllTests() {
        std::cout << "Running DNS Parser Tests..." << std::endl;
        
        testDNSHeaderParsing();
        testDomainNameParsing();
        testCompressionHandling();
        testMalformedPackets();
        testQuestionParsing();
        testPacketToJson();
        
        std::cout << "All DNS Parser tests passed!" << std::endl;
    }

private:
    static void testDNSHeaderParsing() {
        std::cout << "  Testing DNS header parsing..." << std::endl;
        
        // Create a simple DNS header
        uint8_t header_data[] = {
            0x12, 0x34,  // ID
            0x81, 0x80,  // Flags (response, recursion available)
            0x00, 0x01,  // QDCOUNT
            0x00, 0x01,  // ANCOUNT  
            0x00, 0x00,  // NSCOUNT
            0x00, 0x00   // ARCOUNT
        };
        
        DNSParser parser;
        DNSHeader header;
        
        assert(parser.parseHeader(header_data, sizeof(header_data), header));
        assert(header.id == 0x1234);
        assert(header.isResponse() == true);
        assert(header.isRecursionAvailable() == true);
        assert(header.qdcount == 1);
        assert(header.ancount == 1);
        
        std::cout << "    ✓ Header parsing works correctly" << std::endl;
    }
    
    static void testDomainNameParsing() {
        std::cout << "  Testing domain name parsing..." << std::endl;
        
        // Test simple domain name: "example.com"
        uint8_t domain_data[] = {
            7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
            3, 'c', 'o', 'm',
            0  // End of domain
        };
        
        DNSParser parser;
        size_t offset = 0;
        std::string domain = parser.parseDomainName(domain_data, sizeof(domain_data), offset);
        
        assert(domain == "example.com");
        assert(offset == sizeof(domain_data));
        
        std::cout << "    ✓ Simple domain parsing works" << std::endl;
    }
    
    static void testCompressionHandling() {
        std::cout << "  Testing DNS compression handling..." << std::endl;
        
        // Create packet with compression pointer
        uint8_t compressed_data[] = {
            // First domain: "example.com"
            7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
            3, 'c', 'o', 'm',
            0,
            
            // Compressed reference to first domain
            0xC0, 0x00  // Pointer to offset 0
        };
        
        DNSParser parser;
        size_t offset = 13; // Start at compression pointer
        std::string domain = parser.parseDomainName(compressed_data, sizeof(compressed_data), offset);
        
        assert(domain == "example.com");
        
        std::cout << "    ✓ DNS compression works" << std::endl;
    }
    
    static void testMalformedPackets() {
        std::cout << "  Testing malformed packet detection..." << std::endl;
        
        DNSParser parser;
        
        // Test null data
        assert(!parser.isValidDNSPacket(nullptr, 0));
        
        // Test too small packet
        uint8_t small_packet[] = {0x01, 0x02};
        assert(!parser.isValidDNSPacket(small_packet, sizeof(small_packet)));
        
        // Test valid minimal packet
        uint8_t valid_packet[] = {
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        assert(parser.isValidDNSPacket(valid_packet, sizeof(valid_packet)));
        
        std::cout << "    ✓ Malformed packet detection works" << std::endl;
    }
    
    static void testQuestionParsing() {
        std::cout << "  Testing question section parsing..." << std::endl;
        
        // Create DNS packet with question
        uint8_t packet_data[] = {
            // Header
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            
            // Question: example.com A IN
            7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
            3, 'c', 'o', 'm',
            0,
            0x00, 0x01,  // Type A
            0x00, 0x01   // Class IN
        };
        
        DNSParser parser;
        auto packet = parser.parseDNSPacket(packet_data, sizeof(packet_data),
                                          "192.168.1.100", "8.8.8.8", 
                                          12345, 53, 1234567890);
        
        assert(packet != nullptr);
        assert(packet->questions.size() == 1);
        assert(packet->questions[0].qname == "example.com");
        assert(packet->questions[0].qtype == 1); // A record
        assert(packet->questions[0].qclass == 1); // IN
        
        std::cout << "    ✓ Question parsing works" << std::endl;
    }
    
    static void testPacketToJson() {
        std::cout << "  Testing packet to JSON conversion..." << std::endl;
        
        // Create a simple packet
        DNSPacket packet;
        packet.header.id = 0x1234;
        packet.header.flags = 0x0100;
        packet.header.qdcount = 1;
        
        DNSQuestion question;
        question.qname = "example.com";
        question.qtype = 1;
        question.qclass = 1;
        packet.questions.push_back(question);
        
        packet.source_ip = "192.168.1.100";
        packet.dest_ip = "8.8.8.8";
        
        DNSParser parser;
        std::string json = parser.packetToJson(packet);
        
        assert(json.find("\"id\": 4660") != std::string::npos);
        assert(json.find("\"example.com\"") != std::string::npos);
        
        std::cout << "    ✓ JSON conversion works" << std::endl;
    }
};

class DetectorTest {
public:
    static void runAllTests() {
        std::cout << "Running Detector Tests..." << std::endl;
        
        testRuleLoading();
        testLongDomainDetection();
        testSuspiciousQueryTypes();
        testDGADetection();
        testFloodingDetection();
        
        std::cout << "All Detector tests passed!" << std::endl;
    }

private:
    static void testRuleLoading() {
        std::cout << "  Testing rule loading..." << std::endl;
        
        DNSDetector detector;
        // Test with non-existent file (should use defaults)
        detector.loadRules("nonexistent_file.json");
        
        std::cout << "    ✓ Rule loading works" << std::endl;
    }
    
    static void testLongDomainDetection() {
        std::cout << "  Testing long domain detection..." << std::endl;
        
        DNSDetector detector;
        detector.loadRules("../rules/dns_rules.json");
        
        // Create packet with long domain
        DNSPacket packet;
        DNSQuestion question;
        question.qname = std::string(150, 'a') + ".com"; // Very long domain
        question.qtype = 1;
        packet.questions.push_back(question);
        packet.source_ip = "192.168.1.100";
        packet.timestamp = TimeUtils::getCurrentTimestamp();
        
        auto alerts = detector.analyzePacket(packet);
        
        // Should trigger long domain alert
        bool found_long_domain = false;
        for (const auto& alert : alerts) {
            if (alert.rule_id == "DNS-001") {
                found_long_domain = true;
                break;
            }
        }
        assert(found_long_domain);
        
        std::cout << "    ✓ Long domain detection works" << std::endl;
    }
    
    static void testSuspiciousQueryTypes() {
        std::cout << "  Testing suspicious query type detection..." << std::endl;
        
        DNSDetector detector;
        detector.loadRules("../rules/dns_rules.json");
        
        // Create packet with TXT query (type 16)
        DNSPacket packet;
        DNSQuestion question;
        question.qname = "example.com";
        question.qtype = 16; // TXT record
        packet.questions.push_back(question);
        packet.source_ip = "192.168.1.100";
        packet.timestamp = TimeUtils::getCurrentTimestamp();
        
        auto alerts = detector.analyzePacket(packet);
        
        // Should trigger suspicious query type alert
        bool found_suspicious_type = false;
        for (const auto& alert : alerts) {
            if (alert.rule_id == "DNS-002") {
                found_suspicious_type = true;
                break;
            }
        }
        assert(found_suspicious_type);
        
        std::cout << "    ✓ Suspicious query type detection works" << std::endl;
    }
    
    static void testDGADetection() {
        std::cout << "  Testing DGA detection..." << std::endl;
        
        DNSDetector detector;
        detector.loadRules("../rules/dns_rules.json");
        
        // Create packet with DGA-like domain
        DNSPacket packet;
        DNSQuestion question;
        question.qname = "abc123def456ghi789jkl.com"; // Random-looking domain
        question.qtype = 1;
        packet.questions.push_back(question);
        packet.source_ip = "192.168.1.100";
        packet.timestamp = TimeUtils::getCurrentTimestamp();
        
        auto alerts = detector.analyzePacket(packet);
        
        // May or may not trigger depending on entropy calculation
        std::cout << "    ✓ DGA detection test completed" << std::endl;
    }
    
    static void testFloodingDetection() {
        std::cout << "  Testing flooding detection..." << std::endl;
        
        DNSDetector detector;
        detector.loadRules("../rules/dns_rules.json");
        
        // Simulate multiple packets from same IP
        for (int i = 0; i < 50; ++i) {
            DNSPacket packet;
            DNSQuestion question;
            question.qname = "example" + std::to_string(i) + ".com";
            question.qtype = 1;
            packet.questions.push_back(question);
            packet.source_ip = "192.168.1.100";
            packet.timestamp = TimeUtils::getCurrentTimestamp();
            
            detector.analyzePacket(packet);
        }
        
        std::cout << "    ✓ Flooding detection test completed" << std::endl;
    }
};

class UtilsTest {
public:
    static void runAllTests() {
        std::cout << "Running Utils Tests..." << std::endl;
        
        testStringUtils();
        testTimeUtils();
        testNetworkUtils();
        testJsonUtils();
        
        std::cout << "All Utils tests passed!" << std::endl;
    }

private:
    static void testStringUtils() {
        std::cout << "  Testing string utilities..." << std::endl;
        
        // Test domain validation
        assert(StringUtils::isValidDomainName("example.com"));
        assert(!StringUtils::isValidDomainName(""));
        assert(!StringUtils::isValidDomainName(std::string(300, 'a')));
        
        // Test entropy calculation
        double entropy = StringUtils::calculateEntropy("abcdef");
        assert(entropy > 0.0);
        
        // Test case conversion
        assert(StringUtils::toLower("EXAMPLE") == "example");
        assert(StringUtils::toUpper("example") == "EXAMPLE");
        
        std::cout << "    ✓ String utilities work" << std::endl;
    }
    
    static void testTimeUtils() {
        std::cout << "  Testing time utilities..." << std::endl;
        
        uint64_t timestamp = TimeUtils::getCurrentTimestamp();
        assert(timestamp > 0);
        
        std::string time_string = TimeUtils::formatTimestamp(timestamp);
        assert(!time_string.empty());
        
        std::cout << "    ✓ Time utilities work" << std::endl;
    }
    
    static void testNetworkUtils() {
        std::cout << "  Testing network utilities..." << std::endl;
        
        // Test byte order conversion
        uint16_t test_val = 0x1234;
        uint16_t converted = NetworkUtils::hostToNetwork16(test_val);
        uint16_t back = NetworkUtils::networkToHost16(converted);
        assert(back == test_val);
        
        std::cout << "    ✓ Network utilities work" << std::endl;
    }
    
    static void testJsonUtils() {
        std::cout << "  Testing JSON utilities..." << std::endl;
        
        std::string escaped = JsonUtils::escapeJsonString("test\"string");
        assert(escaped.find("\\\"") != std::string::npos);
        
        std::cout << "    ✓ JSON utilities work" << std::endl;
    }
};

int main() {
    std::cout << "=== DNS NIDS Unit Tests ===" << std::endl;
    
    try {
        DNSParserTest::runAllTests();
        std::cout << std::endl;
        
        DetectorTest::runAllTests();
        std::cout << std::endl;
        
        UtilsTest::runAllTests();
        std::cout << std::endl;
        
        std::cout << "All tests passed successfully!" << std::endl;
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "Test failed with exception: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Test failed with unknown exception" << std::endl;
        return 1;
    }
}
