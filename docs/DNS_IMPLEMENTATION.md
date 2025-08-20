# DNS Implementation Guide

## Table of Contents
1. [DNS Protocol Overview](#dns-protocol-overview)
2. [RFC 1035 Compliance](#rfc-1035-compliance)
3. [DNS Header Format](#dns-header-format)
4. [Domain Name Compression](#domain-name-compression)
5. [Message Sections](#message-sections)
6. [Implementation Details](#implementation-details)
7. [Error Handling](#error-handling)
8. [Performance Optimizations](#performance-optimizations)

## DNS Protocol Overview

The Domain Name System (DNS) is a hierarchical distributed naming system that translates human-readable domain names into IP addresses. This document details our implementation of DNS packet parsing according to RFC 1035 specifications.

### Key Concepts

- **Domain Names**: Hierarchical names separated by dots (e.g., `www.example.com`)
- **Resource Records**: Data associated with domain names
- **Query/Response Model**: Clients send queries, servers respond with answers
- **Message Compression**: Technique to reduce packet size by referencing previous names

## RFC 1035 Compliance

Our implementation follows RFC 1035 "Domain Names - Implementation and Specification" with the following key features:

### Supported Features
- ✅ Complete DNS header parsing
- ✅ Question section parsing  
- ✅ Resource record parsing (Answer, Authority, Additional)
- ✅ Domain name compression (pointers)
- ✅ All standard query types (A, NS, CNAME, MX, etc.)
- ✅ Error handling for malformed packets
- ✅ Case-insensitive domain name handling

### Standards Compliance
- **RFC 1035**: Core DNS specification
- **RFC 1123**: Requirements for Internet hosts
- **RFC 2181**: DNS clarifications
- **RFC 3596**: IPv6 support (AAAA records)

## DNS Header Format

The DNS header is a fixed 12-byte structure at the beginning of every DNS message:

```
    0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

### Field Descriptions

| Field | Size | Description |
|-------|------|-------------|
| ID | 16 bits | Unique identifier for matching queries and responses |
| QR | 1 bit | Query (0) or Response (1) |
| Opcode | 4 bits | Operation code (0=standard query, 1=inverse query, etc.) |
| AA | 1 bit | Authoritative Answer flag |
| TC | 1 bit | Truncation flag |
| RD | 1 bit | Recursion Desired flag |
| RA | 1 bit | Recursion Available flag |
| Z | 3 bits | Reserved for future use (must be zero) |
| RCODE | 4 bits | Response code (0=no error, 1=format error, etc.) |
| QDCOUNT | 16 bits | Number of questions |
| ANCOUNT | 16 bits | Number of answer records |
| NSCOUNT | 16 bits | Number of authority records |
| ARCOUNT | 16 bits | Number of additional records |

### Implementation

```cpp
struct DNSHeader {
    uint16_t id;           // Identification
    uint16_t flags;        // Combined flags field
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
```

## Domain Name Compression

DNS uses a compression scheme to reduce packet size by avoiding repetition of domain names. This is crucial for understanding and parsing DNS packets correctly.

### Compression Mechanism

Domain names can be represented in three ways:
1. **Uncompressed**: Sequence of labels ending with zero byte
2. **Compressed**: Pointer to previous occurrence in the packet
3. **Hybrid**: Mix of labels followed by compression pointer

### Compression Pointer Format

```
    0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    | 1  1|                OFFSET                   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

- **Bits 0-1**: Always `11` (0xC0) to indicate compression pointer
- **Bits 2-15**: 14-bit offset pointing to location of domain name in packet

### Examples

**Example 1: Simple Compression**
```
Packet:
  Offset 20: 7 'e' 'x' 'a' 'm' 'p' 'l' 'e' 3 'c' 'o' 'm' 0
  Offset 40: 0xC0 0x14  // Points to offset 20 (0x14)
```

**Example 2: Hybrid Compression**
```
Packet:
  Offset 20: 7 'e' 'x' 'a' 'm' 'p' 'l' 'e' 3 'c' 'o' 'm' 0
  Offset 40: 3 'w' 'w' 'w' 0xC0 0x14  // "www" + pointer to "example.com"
  Result: "www.example.com"
```

### Implementation

```cpp
std::string DNSParser::parseDomainName(const uint8_t* data, size_t len, size_t& offset) {
    std::string domain_name;
    std::vector<size_t> visited_offsets; // Loop detection
    bool jumped = false;
    size_t original_offset = offset;
    
    while (offset < len) {
        uint8_t label_len = data[offset];
        
        // Check for compression pointer
        if (isCompressedPointer(label_len)) {
            if (offset + 1 >= len) return "";
            
            uint16_t pointer_offset = getCompressionOffset(data, offset);
            
            // Detect compression loops
            for (size_t visited : visited_offsets) {
                if (visited == pointer_offset) {
                    return ""; // Loop detected - invalid packet
                }
            }
            visited_offsets.push_back(pointer_offset);
            
            // Remember position after pointer for return
            if (!jumped) {
                original_offset = offset + 2;
                jumped = true;
            }
            
            offset = pointer_offset;
            continue;
        }
        
        // End of domain name
        if (label_len == 0) {
            offset++;
            break;
        }
        
        // Validate label length
        if (label_len > MAX_LABEL_LENGTH || offset + 1 + label_len > len) {
            return "";
        }
        
        // Add dot separator if not first label
        if (!domain_name.empty()) {
            domain_name += ".";
        }
        
        // Extract label
        domain_name.append(reinterpret_cast<const char*>(data + offset + 1), label_len);
        offset += 1 + label_len;
    }
    
    // Restore offset if we followed a pointer
    if (jumped) {
        offset = original_offset;
    }
    
    return domain_name;
}

bool DNSParser::isCompressedPointer(uint8_t byte) const {
    return (byte & 0xC0) == 0xC0; // Check if top two bits are 11
}

uint16_t DNSParser::getCompressionOffset(const uint8_t* data, size_t offset) const {
    uint16_t pointer = parseUint16(data, offset);
    return pointer & 0x3FFF; // Clear compression bits, keep 14-bit offset
}
```

### Compression Edge Cases

1. **Infinite Loops**: Malformed packets may contain circular references
2. **Invalid Offsets**: Pointers may reference non-existent or invalid locations
3. **Forward References**: Pointers should only reference earlier positions
4. **Multiple Jumps**: Domain name may contain multiple compression pointers

## Message Sections

DNS messages are divided into five sections:

### 1. Header Section (Always Present)
Fixed 12-byte header described above.

### 2. Question Section
Contains the query being asked:

```
    0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                     QNAME                     /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

| Field | Description |
|-------|-------------|
| QNAME | Domain name being queried |
| QTYPE | Query type (1=A, 2=NS, 5=CNAME, etc.) |
| QCLASS | Query class (1=IN for Internet) |

### 3. Answer Section
Contains resource records answering the query.

### 4. Authority Section
Contains resource records for authoritative name servers.

### 5. Additional Section
Contains additional resource records that may be useful.

### Resource Record Format

```cpp
struct DNSResourceRecord {
    std::string name;      // Domain name
    uint16_t type;         // Record type
    uint16_t rclass;       // Record class
    uint32_t ttl;          // Time to live
    uint16_t rdlength;     // Resource data length
    std::vector<uint8_t> rdata; // Resource data
};
```

## Implementation Details

### Query Types

| Type | Value | Description |
|------|-------|-------------|
| A | 1 | IPv4 address |
| NS | 2 | Name server |
| CNAME | 5 | Canonical name |
| MX | 15 | Mail exchange |
| TXT | 16 | Text record |
| AAAA | 28 | IPv6 address |
| ANY | 255 | Any available records |

### Response Codes (RCODE)

| Code | Name | Description |
|------|------|-------------|
| 0 | NOERROR | No error |
| 1 | FORMERR | Format error |
| 2 | SERVFAIL | Server failure |
| 3 | NXDOMAIN | Name does not exist |
| 4 | NOTIMP | Not implemented |
| 5 | REFUSED | Query refused |

### Parsing Algorithm

```cpp
std::unique_ptr<DNSPacket> DNSParser::parseDNSPacket(
    const uint8_t* packet_data, size_t packet_len,
    const std::string& src_ip, const std::string& dst_ip,
    uint16_t src_port, uint16_t dst_port, uint64_t timestamp) {
    
    // 1. Validate minimum packet size
    if (!packet_data || packet_len < DNS_HEADER_SIZE) {
        return nullptr;
    }
    
    auto packet = std::make_unique<DNSPacket>();
    
    // 2. Set metadata
    packet->source_ip = src_ip;
    packet->dest_ip = dst_ip;
    packet->source_port = src_port;
    packet->dest_port = dst_port;
    packet->timestamp = timestamp;
    packet->packet_size = packet_len;
    
    // 3. Parse DNS header
    if (!parseHeader(packet_data, packet_len, packet->header)) {
        return nullptr;
    }
    
    size_t offset = DNS_HEADER_SIZE;
    
    // 4. Parse questions
    if (packet->header.qdcount > 0) {
        if (!parseQuestions(packet_data, packet_len, offset, 
                           packet->questions, packet->header.qdcount)) {
            return nullptr;
        }
    }
    
    // 5. Parse answer records
    if (packet->header.ancount > 0) {
        if (!parseResourceRecords(packet_data, packet_len, offset,
                                 packet->answers, packet->header.ancount)) {
            return nullptr;
        }
    }
    
    // 6. Parse authority records
    if (packet->header.nscount > 0) {
        if (!parseResourceRecords(packet_data, packet_len, offset,
                                 packet->authority, packet->header.nscount)) {
            return nullptr;
        }
    }
    
    // 7. Parse additional records
    if (packet->header.arcount > 0) {
        if (!parseResourceRecords(packet_data, packet_len, offset,
                                 packet->additional, packet->header.arcount)) {
            return nullptr;
        }
    }
    
    return packet;
}
```

## Error Handling

### Validation Checks

1. **Packet Size Validation**:
   ```cpp
   if (packet_len < DNS_HEADER_SIZE || packet_len > MAX_DNS_PACKET_SIZE) {
       return false;
   }
   ```

2. **Field Range Validation**:
   ```cpp
   if (header.qdcount > MAX_QUESTIONS || 
       header.ancount > MAX_ANSWERS) {
       return false;
   }
   ```

3. **Domain Name Validation**:
   ```cpp
   if (domain.length() > MAX_DOMAIN_NAME_LENGTH) {
       return false;
   }
   
   // Check individual label lengths
   for (const auto& label : labels) {
       if (label.length() > MAX_LABEL_LENGTH) {
           return false;
       }
   }
   ```

4. **Compression Pointer Validation**:
   ```cpp
   uint16_t offset = getCompressionOffset(data, pos);
   if (offset >= packet_len || offset >= pos) {
       return ""; // Invalid or forward reference
   }
   ```

### Error Recovery Strategies

1. **Graceful Degradation**: Continue parsing remaining sections even if one fails
2. **Best Effort Parsing**: Extract as much valid data as possible
3. **Error Logging**: Log parsing failures for debugging
4. **Fallback Handling**: Provide partial packet information when possible

## Performance Optimizations

### Memory Management

1. **Object Pooling**:
   ```cpp
   class DNSPacketPool {
       std::queue<std::unique_ptr<DNSPacket>> available_packets;
       
       std::unique_ptr<DNSPacket> acquire() {
           if (available_packets.empty()) {
               return std::make_unique<DNSPacket>();
           }
           auto packet = std::move(available_packets.front());
           available_packets.pop();
           packet->reset(); // Clear previous data
           return packet;
       }
       
       void release(std::unique_ptr<DNSPacket> packet) {
           available_packets.push(std::move(packet));
       }
   };
   ```

2. **String Optimization**:
   ```cpp
   // Use string_view for parsing to avoid unnecessary copies
   std::string_view extractLabel(const uint8_t* data, size_t offset, size_t length) {
       return std::string_view(reinterpret_cast<const char*>(data + offset), length);
   }
   ```

3. **Buffer Reuse**:
   ```cpp
   class ParseContext {
       std::string domain_buffer; // Reused across parsing calls
       std::vector<std::string> label_cache;
   public:
       void reset() {
           domain_buffer.clear();
           label_cache.clear();
       }
   };
   ```

### Parsing Optimizations

1. **Early Termination**:
   ```cpp
   // Skip parsing sections we don't need
   if (!need_answers && header.ancount > 0) {
       skipResourceRecords(data, len, offset, header.ancount);
   }
   ```

2. **Lazy Parsing**:
   ```cpp
   struct LazyDNSPacket {
       const uint8_t* raw_data;
       size_t data_length;
       mutable bool questions_parsed = false;
       mutable std::vector<DNSQuestion> questions;
       
       const std::vector<DNSQuestion>& getQuestions() const {
           if (!questions_parsed) {
               parseQuestions();
               questions_parsed = true;
           }
           return questions;
       }
   };
   ```

3. **SIMD Operations**:
   ```cpp
   // Use SIMD for fast string operations where supported
   #ifdef __SSE2__
   bool fastCompareLabels(const char* a, const char* b, size_t len) {
       // SIMD-optimized string comparison
   }
   #endif
   ```

### Caching Strategies

1. **Domain Name Cache**:
   ```cpp
   class DomainNameCache {
       std::unordered_map<uint32_t, std::string> cache;
   public:
       std::string lookup(const uint8_t* data, size_t offset, size_t packet_len) {
           uint32_t key = computeHash(data, offset, packet_len);
           auto it = cache.find(key);
           if (it != cache.end()) {
               return it->second;
           }
           
           std::string domain = parseDomainName(data, offset, packet_len);
           cache[key] = domain;
           return domain;
       }
   };
   ```

2. **Parsing Result Cache**:
   ```cpp
   // Cache parsed packets for repeated analysis
   std::unordered_map<uint64_t, std::unique_ptr<DNSPacket>> parse_cache;
   ```

## Testing and Validation

### Test Cases

1. **Valid Packets**:
   - Standard queries and responses
   - Various query types
   - Compressed domain names
   - Multiple sections

2. **Edge Cases**:
   - Maximum length domain names
   - Deeply nested compression
   - Empty sections
   - Minimal packets

3. **Malformed Packets**:
   - Truncated packets
   - Invalid compression pointers
   - Circular references
   - Out-of-bounds accesses

4. **Performance Tests**:
   - Large packet processing
   - High-frequency parsing
   - Memory usage profiling

### Validation Tools

```bash
# Use dig to generate test packets
dig @8.8.8.8 example.com > normal_query.txt

# Use tcpdump to capture real DNS traffic
sudo tcpdump -w dns_traffic.pcap port 53

# Validate against known good parsers
nslookup example.com
```

## References

- [RFC 1035 - Domain Names - Implementation and Specification](https://tools.ietf.org/html/rfc1035)
- [RFC 1123 - Requirements for Internet Hosts](https://tools.ietf.org/html/rfc1123)
- [RFC 2181 - Clarifications to the DNS Specification](https://tools.ietf.org/html/rfc2181)
- [RFC 3596 - DNS Extensions to Support IP Version 6](https://tools.ietf.org/html/rfc3596)
- [DNS Message Compression](https://www.rfc-editor.org/rfc/rfc1035.html#section-4.1.4)

---

This implementation guide ensures RFC 1035 compliance while providing practical guidance for building a robust, performant DNS parser suitable for security applications.
