#!/usr/bin/env python3
"""
Memory Dump Analyzer
Analyzes memory dumps for forensic artifacts including processes, network connections, and strings
"""

import struct
import re
import argparse
import json
from collections import defaultdict
import hashlib

class MemoryDumpAnalyzer:
    def __init__(self, dump_file):
        self.dump_file = dump_file
        self.processes = []
        self.network_connections = []
        self.suspicious_strings = []
        
    def find_processes(self):
        """Find process structures in memory dump"""
        # This is a simplified implementation
        # Real memory analysis would parse actual process structures
        process_signatures = [
            b'System',
            b'smss.exe',
            b'csrss.exe',
            b'winlogon.exe',
            b'services.exe',
            b'lsass.exe',
            b'svchost.exe',
            b'explorer.exe'
        ]
        
        with open(self.dump_file, 'rb') as f:
            content = f.read()
            
            for signature in process_signatures:
                offset = 0
                while True:
                    pos = content.find(signature, offset)
                    if pos == -1:
                        break
                    
                    # Extract surrounding context
                    start = max(0, pos - 100)
                    end = min(len(content), pos + 100)
                    context = content[start:end]
                    
                    process_info = {
                        'name': signature.decode('utf-8', errors='ignore'),
                        'offset': pos,
                        'context': context.hex()
                    }
                    self.processes.append(process_info)
                    offset = pos + 1
    
    def find_network_artifacts(self):
        """Find network-related artifacts in memory"""
        ip_pattern = rb'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        url_pattern = rb'https?://[^\s<>"\'|\\^\`\[\]{}]*'
        
        with open(self.dump_file, 'rb') as f:
            content = f.read()
            
            # Find IP addresses
            for match in re.finditer(ip_pattern, content):
                ip = match.group().decode('utf-8', errors='ignore')
                if self.is_valid_ip(ip):
                    self.network_connections.append({
                        'type': 'IP Address',
                        'value': ip,
                        'offset': match.start()
                    })
            
            # Find URLs
            for match in re.finditer(url_pattern, content):
                url = match.group().decode('utf-8', errors='ignore')
                self.network_connections.append({
                    'type': 'URL',
                    'value': url,
                    'offset': match.start()
                })
    
    def is_valid_ip(self, ip):
        """Validate IP address format"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            for part in parts:
                if not 0 <= int(part) <= 255:
                    return False
            return True
        except ValueError:
            return False
    
    def find_suspicious_strings(self):
        """Find potentially suspicious strings in memory"""
        suspicious_patterns = [
            rb'cmd\.exe',
            rb'powershell',
            rb'password',
            rb'admin',
            rb'rootkit',
            rb'keylog',
            rb'backdoor',
            rb'trojan',
            rb'virus',
            rb'malware',
            rb'exploit',
            rb'payload',
            rb'shell',
            rb'reverse',
            rb'bind',
            rb'nc\.exe',
            rb'netcat'
        ]
        
        with open(self.dump_file, 'rb') as f:
            content = f.read()
            
            for pattern in suspicious_patterns:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    string_val = match.group().decode('utf-8', errors='ignore')
                    
                    # Get context around the match
                    start = max(0, match.start() - 50)
                    end = min(len(content), match.end() + 50)
                    context = content[start:end].decode('utf-8', errors='ignore')
                    
                    self.suspicious_strings.append({
                        'string': string_val,
                        'offset': match.start(),
                        'context': context
                    })
    
    def extract_strings(self, min_length=4):
        """Extract all printable strings from memory dump"""
        strings = []
        with open(self.dump_file, 'rb') as f:
            content = f.read()
            
            # ASCII strings
            ascii_pattern = rb'[\x20-\x7E]{' + str(min_length).encode() + rb',}'
            for match in re.finditer(ascii_pattern, content):
                string_val = match.group().decode('ascii')
                strings.append({
                    'type': 'ASCII',
                    'value': string_val,
                    'offset': match.start(),
                    'length': len(string_val)
                })
            
            # Unicode strings (simplified)
            unicode_pattern = rb'(?:[\x20-\x7E]\x00){' + str(min_length).encode() + rb',}'
            for match in re.finditer(unicode_pattern, content):
                try:
                    string_val = match.group().decode('utf-16le')
                    strings.append({
                        'type': 'Unicode',
                        'value': string_val,
                        'offset': match.start(),
                        'length': len(string_val)
                    })
                except:
                    pass
        
        return strings
    
    def analyze_pe_headers(self):
        """Find and analyze PE headers in memory"""
        pe_headers = []
        mz_signature = b'MZ'
        pe_signature = b'PE\x00\x00'
        
        with open(self.dump_file, 'rb') as f:
            content = f.read()
            
            # Find MZ headers
            offset = 0
            while True:
                pos = content.find(mz_signature, offset)
                if pos == -1:
                    break
                
                # Check if it's followed by a valid PE header
                try:
                    # Read e_lfanew offset (at position 0x3C from MZ)
                    if pos + 0x3C + 4 < len(content):
                        e_lfanew = struct.unpack('<L', content[pos + 0x3C:pos + 0x3C + 4])[0]
                        pe_pos = pos + e_lfanew
                        
                        if pe_pos + 4 < len(content):
                            if content[pe_pos:pe_pos + 4] == pe_signature:
                                pe_headers.append({
                                    'mz_offset': pos,
                                    'pe_offset': pe_pos,
                                    'e_lfanew': e_lfanew
                                })
                except:
                    pass
                
                offset = pos + 1
        
        return pe_headers
    
    def generate_report(self):
        """Generate comprehensive analysis report"""
        self.find_processes()
        self.find_network_artifacts()
        self.find_suspicious_strings()
        
        report = {
            'file_info': {
                'filename': self.dump_file,
                'file_size': self.get_file_size()
            },
            'processes': self.processes,
            'network_artifacts': self.network_connections,
            'suspicious_strings': self.suspicious_strings,
            'pe_headers': self.analyze_pe_headers(),
            'statistics': {
                'total_processes': len(self.processes),
                'total_network_artifacts': len(self.network_connections),
                'total_suspicious_strings': len(self.suspicious_strings)
            }
        }
        
        return report
    
    def get_file_size(self):
        """Get file size"""
        try:
            with open(self.dump_file, 'rb') as f:
                f.seek(0, 2)  # Seek to end
                return f.tell()
        except:
            return 0

def main():
    parser = argparse.ArgumentParser(description='Analyze memory dumps for forensic artifacts')
    parser.add_argument('dump_file', help='Path to memory dump file')
    parser.add_argument('-o', '--output', help='Output JSON file')
    parser.add_argument('-s', '--strings', action='store_true', help='Extract all strings')
    parser.add_argument('--min-length', type=int, default=4, help='Minimum string length')
    
    args = parser.parse_args()
    
    analyzer = MemoryDumpAnalyzer(args.dump_file)
    report = analyzer.generate_report()
    
    if args.strings:
        strings = analyzer.extract_strings(args.min_length)
        report['strings'] = strings
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"Analysis report saved to {args.output}")
    else:
        print(json.dumps(report, indent=2))

if __name__ == '__main__':
    main()
