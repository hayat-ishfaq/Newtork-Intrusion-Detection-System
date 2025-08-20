#include "dns_parser.hpp"
#include "utils.hpp"
#include <cstring>
#include <iostream>
#include <sstream>

#ifdef _WIN32
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#endif

DNSParser::DNSParser() {
    // Initialize parser
}

DNSParser::~DNSParser() {
    // Cleanup
}

std::unique_ptr<DNSPacket> DNSParser::parseDNSPacket(const uint8_t* packet_data, 
                                                      size_t packet_len,
                                                      const std::string& src_ip,
                                                      const std::string& dst_ip,
                                                      uint16_t src_port,
                                                      uint16_t dst_port,
                                                      uint64_t timestamp) {
    if (!packet_data || packet_len < DNS_HEADER_SIZE) {
        return nullptr;
    }
    
    auto packet = std::make_unique<DNSPacket>();
    
    // Set metadata
    packet->source_ip = src_ip;
    packet->dest_ip = dst_ip;
    packet->source_port = src_port;
    packet->dest_port = dst_port;
    packet->timestamp = timestamp;
    packet->packet_size = packet_len;
    
    // Parse DNS header
    if (!parseHeader(packet_data, packet_len, packet->header)) {
        return nullptr;
    }
    
    size_t offset = DNS_HEADER_SIZE;
    
    // Parse questions
    if (packet->header.qdcount > 0) {
        if (!parseQuestions(packet_data, packet_len, offset, 
                           packet->questions, packet->header.qdcount)) {
            return nullptr;
        }
    }
    
    // Parse answers
    if (packet->header.ancount > 0) {
        if (!parseResourceRecords(packet_data, packet_len, offset,
                                 packet->answers, packet->header.ancount)) {
            return nullptr;
        }
    }
    
    // Parse authority records
    if (packet->header.nscount > 0) {
        if (!parseResourceRecords(packet_data, packet_len, offset,
                                 packet->authority, packet->header.nscount)) {
            return nullptr;
        }
    }
    
    // Parse additional records
    if (packet->header.arcount > 0) {
        if (!parseResourceRecords(packet_data, packet_len, offset,
                                 packet->additional, packet->header.arcount)) {
            return nullptr;
        }
    }
    
    return packet;
}

bool DNSParser::parseHeader(const uint8_t* data, size_t len, DNSHeader& header) {
    if (len < DNS_HEADER_SIZE) {
        return false;
    }
    
    header.id = parseUint16(data, 0);
    header.flags = parseUint16(data, 2);
    header.qdcount = parseUint16(data, 4);
    header.ancount = parseUint16(data, 6);
    header.nscount = parseUint16(data, 8);
    header.arcount = parseUint16(data, 10);
    
    return true;
}

bool DNSParser::parseQuestions(const uint8_t* data, size_t len, size_t& offset,
                              std::vector<DNSQuestion>& questions, uint16_t count) {
    questions.reserve(count);
    
    for (uint16_t i = 0; i < count; ++i) {
        if (offset >= len) {
            return false;
        }
        
        DNSQuestion question;
        
        // Parse QNAME
        question.qname = parseDomainName(data, len, offset);
        if (question.qname.empty()) {
            return false;
        }
        
        // Check if we have enough bytes for QTYPE and QCLASS
        if (offset + 4 > len) {
            return false;
        }
        
        // Parse QTYPE and QCLASS
        question.qtype = parseUint16(data, offset);
        offset += 2;
        question.qclass = parseUint16(data, offset);
        offset += 2;
        
        questions.push_back(question);
    }
    
    return true;
}

bool DNSParser::parseResourceRecords(const uint8_t* data, size_t len, size_t& offset,
                                    std::vector<DNSResourceRecord>& records, uint16_t count) {
    records.reserve(count);
    
    for (uint16_t i = 0; i < count; ++i) {
        if (offset >= len) {
            return false;
        }
        
        DNSResourceRecord record;
        
        // Parse NAME
        record.name = parseDomainName(data, len, offset);
        if (record.name.empty()) {
            return false;
        }
        
        // Check if we have enough bytes for TYPE, CLASS, TTL, and RDLENGTH
        if (offset + 10 > len) {
            return false;
        }
        
        // Parse TYPE, CLASS, TTL, and RDLENGTH
        record.type = parseUint16(data, offset);
        offset += 2;
        record.rclass = parseUint16(data, offset);
        offset += 2;
        record.ttl = parseUint32(data, offset);
        offset += 4;
        record.rdlength = parseUint16(data, offset);
        offset += 2;
        
        // Parse RDATA
        if (offset + record.rdlength > len) {
            return false;
        }
        
        record.rdata.resize(record.rdlength);
        std::memcpy(record.rdata.data(), data + offset, record.rdlength);
        offset += record.rdlength;
        
        records.push_back(record);
    }
    
    return true;
}

std::string DNSParser::parseDomainName(const uint8_t* data, size_t len, size_t& offset) {
    std::string domain_name;
    std::vector<size_t> visited_offsets; // To detect compression loops
    bool jumped = false;
    size_t original_offset = offset;
    
    while (offset < len) {
        uint8_t label_len = data[offset];
        
        // Check for compression
        if (isCompressedPointer(label_len)) {
            if (offset + 1 >= len) {
                return "";
            }
            
            uint16_t compression_offset = getCompressionOffset(data, offset);
            
            // Check for infinite loops
            for (size_t visited : visited_offsets) {
                if (visited == compression_offset) {
                    return ""; // Loop detected
                }
            }
            visited_offsets.push_back(compression_offset);
            
            if (!jumped) {
                original_offset = offset + 2;
                jumped = true;
            }
            
            offset = compression_offset;
            
            if (offset >= len) {
                return "";
            }
            
            continue;
        }
        
        // End of domain name
        if (label_len == 0) {
            offset++;
            break;
        }
        
        // Check label length validity
        if (label_len > MAX_LABEL_LENGTH || offset + 1 + label_len > len) {
            return "";
        }
        
        // Add dot separator if not first label
        if (!domain_name.empty()) {
            domain_name += ".";
        }
        
        // Extract label
        std::string label(reinterpret_cast<const char*>(data + offset + 1), label_len);
        domain_name += label;
        
        offset += 1 + label_len;
    }
    
    // If we jumped due to compression, restore the offset
    if (jumped) {
        offset = original_offset;
    }
    
    // Validate domain name
    if (!isValidDomainName(domain_name)) {
        return "";
    }
    
    return domain_name;
}

bool DNSParser::isCompressedPointer(uint8_t byte) const {
    return (byte & COMPRESSION_MASK) == COMPRESSION_MASK;
}

uint16_t DNSParser::getCompressionOffset(const uint8_t* data, size_t offset) const {
    uint16_t pointer = parseUint16(data, offset);
    return pointer & 0x3FFF; // Remove compression bits
}

uint16_t DNSParser::parseUint16(const uint8_t* data, size_t offset) const {
    return NetworkUtils::networkToHost16(*reinterpret_cast<const uint16_t*>(data + offset));
}

uint32_t DNSParser::parseUint32(const uint8_t* data, size_t offset) const {
    return NetworkUtils::networkToHost32(*reinterpret_cast<const uint32_t*>(data + offset));
}

bool DNSParser::isValidDomainName(const std::string& name) const {
    if (name.empty() || name.length() > MAX_DOMAIN_NAME_LENGTH) {
        return false;
    }
    
    return StringUtils::isValidDomainName(name);
}

bool DNSParser::isValidDNSPacket(const uint8_t* data, size_t len) {
    if (!data || len < DNS_HEADER_SIZE) {
        return false;
    }
    
    // Basic header validation
    DNSHeader header;
    if (!parseHeader(data, len, header)) {
        return false;
    }
    
    // Check if counts are reasonable
    const uint16_t max_records = 1000; // Arbitrary but reasonable limit
    if (header.qdcount > max_records || header.ancount > max_records ||
        header.nscount > max_records || header.arcount > max_records) {
        return false;
    }
    
    return true;
}

std::string DNSParser::packetToJson(const DNSPacket& packet) {
    std::ostringstream json;
    
    json << "{\n";
    json << "  \"header\": {\n";
    json << "    \"id\": " << packet.header.id << ",\n";
    json << "    \"flags\": " << packet.header.flags << ",\n";
    json << "    \"qr\": " << (packet.header.isResponse() ? 1 : 0) << ",\n";
    json << "    \"opcode\": " << static_cast<int>(packet.header.getOpcode()) << ",\n";
    json << "    \"aa\": " << (packet.header.isAuthoritative() ? 1 : 0) << ",\n";
    json << "    \"tc\": " << (packet.header.isTruncated() ? 1 : 0) << ",\n";
    json << "    \"rd\": " << (packet.header.isRecursionDesired() ? 1 : 0) << ",\n";
    json << "    \"ra\": " << (packet.header.isRecursionAvailable() ? 1 : 0) << ",\n";
    json << "    \"rcode\": " << static_cast<int>(packet.header.getRCode()) << ",\n";
    json << "    \"qdcount\": " << packet.header.qdcount << ",\n";
    json << "    \"ancount\": " << packet.header.ancount << ",\n";
    json << "    \"nscount\": " << packet.header.nscount << ",\n";
    json << "    \"arcount\": " << packet.header.arcount << "\n";
    json << "  },\n";
    
    // Questions
    json << "  \"questions\": [\n";
    for (size_t i = 0; i < packet.questions.size(); ++i) {
        const auto& q = packet.questions[i];
        json << "    {\n";
        json << "      \"qname\": \"" << JsonUtils::escapeJsonString(q.qname) << "\",\n";
        json << "      \"qtype\": " << q.qtype << ",\n";
        json << "      \"qclass\": " << q.qclass << "\n";
        json << "    }";
        if (i < packet.questions.size() - 1) json << ",";
        json << "\n";
    }
    json << "  ],\n";
    
    // Metadata
    json << "  \"metadata\": {\n";
    json << "    \"source_ip\": \"" << packet.source_ip << "\",\n";
    json << "    \"dest_ip\": \"" << packet.dest_ip << "\",\n";
    json << "    \"source_port\": " << packet.source_port << ",\n";
    json << "    \"dest_port\": " << packet.dest_port << ",\n";
    json << "    \"timestamp\": " << packet.timestamp << ",\n";
    json << "    \"packet_size\": " << packet.packet_size << "\n";
    json << "  }\n";
    json << "}";
    
    return json.str();
}
