# Sample PCAP Files

This directory contains sample PCAP files for testing the DNS NIDS:

## normal.pcap
Contains legitimate DNS traffic including:
- Standard A record queries
- MX record lookups
- CNAME resolution
- Normal response patterns

## attack.pcap  
Contains malicious/suspicious DNS traffic including:
- DNS tunneling attempts (long domain names)
- Suspicious query types (TXT, NULL, ANY)
- DGA-generated domains
- DNS flooding patterns
- Malformed packets

## Usage

To use these files for testing:

```bash
# Test with normal traffic
./nids_dns -r tests/dns/normal.pcap -R rules/dns_rules.json -v

# Test with attack traffic
./nids_dns -r tests/dns/attack.pcap -R rules/dns_rules.json -l attack_alerts.log -v
```

## Generating Your Own Test Files

You can generate test PCAP files using tools like:

```bash
# Capture live DNS traffic
sudo tcpdump -w normal.pcap port 53 -c 100

# Generate queries with dig
dig @8.8.8.8 example.com
dig @8.8.8.8 google.com MX
dig @8.8.8.8 facebook.com AAAA

# Create malicious patterns
dig @8.8.8.8 $(python -c "print('a'*150 + '.com')")  # Long domain
dig @8.8.8.8 example.com TXT                          # Suspicious type
```

Note: Actual PCAP files are binary and cannot be included in this text-based project structure. In a real implementation, you would generate these using the methods above.
