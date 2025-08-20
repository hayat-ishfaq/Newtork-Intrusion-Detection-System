#ifndef DNS_PARSER_HPP
#define DNS_PARSER_HPP

#include <cstdint>
#include <string>
#include <vector>
#include <memory>

// DNS Header Structure (12 bytes)
struct DNSHeader {
    uint16_t id;           // Identification
    uint16_t flags;        // Flags (QR, Opcode, AA, TC, RD, RA, RCODE)
    uint16_t qdcount;      // Question count
    uint16_t ancount;      // Answer count
    uint16_t nscount;      // Authority count
    uint16_t arcount;      // Additional count
    
    // Helper methods for flag parsing
    bool isQuery() const { return !(flags & 0x8000); }
    bool isResponse() const { return flags & 0x8000; }
    uint8_t getOpcode() const { return (flags >> 11) & 0x0F; }
    bool isAuthoritative() const { return flags & 0x0400; }
    bool isTruncated() const { return flags & 0x0200; }
    bool isRecursionDesired() const { return flags & 0x0100; }
    bool isRecursionAvailable() const { return flags & 0x0080; }
    uint8_t getRCode() const { return flags & 0x000F; }
};

// DNS Question Structure
struct DNSQuestion {
    std::string qname;     // Domain name
    uint16_t qtype;        // Query type
    uint16_t qclass;       // Query class
    
    // Helper methods for type checking
    bool isA() const { return qtype == 1; }
    bool isNS() const { return qtype == 2; }
    bool isCNAME() const { return qtype == 5; }
    bool isMX() const { return qtype == 15; }
    bool isTXT() const { return qtype == 16; }
    bool isAAAA() const { return qtype == 28; }
    bool isANY() const { return qtype == 255; }
    bool isNULL() const { return qtype == 10; }
};

// DNS Resource Record Structure
struct DNSResourceRecord {
    std::string name;
    uint16_t type;
    uint16_t rclass;
    uint32_t ttl;
    uint16_t rdlength;
    std::vector<uint8_t> rdata;
};

// Complete DNS Packet Structure
struct DNSPacket {
    DNSHeader header;
    std::vector<DNSQuestion> questions;
    std::vector<DNSResourceRecord> answers;
    std::vector<DNSResourceRecord> authority;
    std::vector<DNSResourceRecord> additional;
    
    // Metadata
    std::string source_ip;
    std::string dest_ip;
    uint16_t source_port;
    uint16_t dest_port;
    uint64_t timestamp;
    size_t packet_size;
};

class DNSParser {
public:
    DNSParser();
    ~DNSParser();
    
    // Main parsing function
    std::unique_ptr<DNSPacket> parseDNSPacket(const uint8_t* packet_data, 
                                              size_t packet_len,
                                              const std::string& src_ip,
                                              const std::string& dst_ip,
                                              uint16_t src_port,
                                              uint16_t dst_port,
                                              uint64_t timestamp);
    
    // Helper functions
    bool isValidDNSPacket(const uint8_t* data, size_t len);
    std::string packetToJson(const DNSPacket& packet);
    
    // Domain name parsing with compression support (public for testing)
    std::string parseDomainName(const uint8_t* data, size_t len, size_t& offset);
    
private:
    // Internal parsing functions
    bool parseHeader(const uint8_t* data, size_t len, DNSHeader& header);
    bool parseQuestions(const uint8_t* data, size_t len, size_t& offset, 
                       std::vector<DNSQuestion>& questions, uint16_t count);
    bool parseResourceRecords(const uint8_t* data, size_t len, size_t& offset,
                             std::vector<DNSResourceRecord>& records, uint16_t count);
    
    // Compression and utility functions
    bool isCompressedPointer(uint8_t byte) const;
    uint16_t getCompressionOffset(const uint8_t* data, size_t offset) const;
    
    // Utility functions
    uint16_t parseUint16(const uint8_t* data, size_t offset) const;
    uint32_t parseUint32(const uint8_t* data, size_t offset) const;
    bool isValidDomainName(const std::string& name) const;
    
    // Constants
    static const size_t DNS_HEADER_SIZE = 12;
    static const size_t MAX_DOMAIN_NAME_LENGTH = 253;
    static const size_t MAX_LABEL_LENGTH = 63;
    static const uint8_t COMPRESSION_MASK = 0xC0;
};

#endif // DNS_PARSER_HPP
