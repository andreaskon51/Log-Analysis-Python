#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <regex>
#include <iomanip>
#include <sstream>
#include <map>
#include <cstring>

struct ProcessInfo {
    std::string name;
    uint64_t offset;
    uint32_t pid;
    uint32_t ppid;
    std::string command_line;
};

struct NetworkConnection {
    std::string protocol;
    std::string local_addr;
    uint16_t local_port;
    std::string remote_addr;
    uint16_t remote_port;
    std::string state;
    uint64_t offset;
};

class MemoryForensics {
private:
    std::vector<uint8_t> memory_data;
    std::vector<ProcessInfo> processes;
    std::vector<NetworkConnection> connections;
    std::vector<std::string> suspicious_strings;

public:
    bool loadMemoryDump(const std::string& filename) {
        std::ifstream file(filename, std::ios::binary | std::ios::ate);
        if (!file) {
            std::cerr << "Failed to open memory dump: " << filename << std::endl;
            return false;
        }

        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);

        memory_data.resize(size);
        if (!file.read(reinterpret_cast<char*>(memory_data.data()), size)) {
            std::cerr << "Failed to read memory dump" << std::endl;
            return false;
        }

        std::cout << "Loaded memory dump: " << size << " bytes" << std::endl;
        return true;
    }

    void findProcessStructures() {
        // Look for EPROCESS structures (simplified)
        const std::vector<std::string> process_names = {
            "System", "smss.exe", "csrss.exe", "winlogon.exe",
            "services.exe", "lsass.exe", "svchost.exe", "explorer.exe",
            "cmd.exe", "powershell.exe", "notepad.exe"
        };

        for (const auto& proc_name : process_names) {
            size_t pos = 0;
            while ((pos = findBytes(proc_name, pos)) != std::string::npos) {
                ProcessInfo proc;
                proc.name = proc_name;
                proc.offset = pos;
                proc.pid = extractDword(pos - 20);  // Approximate PID location
                proc.ppid = extractDword(pos - 16); // Approximate PPID location
                
                processes.push_back(proc);
                pos++;
            }
        }

        std::cout << "Found " << processes.size() << " process references" << std::endl;
    }

    void findNetworkArtifacts() {
        // IPv4 address pattern
        std::regex ipv4_pattern(R"(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)");
        
        // Convert memory to string for regex searching
        std::string memory_str(memory_data.begin(), memory_data.end());
        
        std::sregex_iterator iter(memory_str.begin(), memory_str.end(), ipv4_pattern);
        std::sregex_iterator end;

        for (; iter != end; ++iter) {
            std::smatch match = *iter;
            std::string ip = match.str();
            
            if (isValidIP(ip)) {
                NetworkConnection conn;
                conn.protocol = "Unknown";
                conn.local_addr = ip;
                conn.offset = match.position();
                connections.push_back(conn);
            }
        }

        std::cout << "Found " << connections.size() << " network artifacts" << std::endl;
    }

    void findSuspiciousStrings() {
        const std::vector<std::string> suspicious_keywords = {
            "password", "admin", "root", "shell", "exploit",
            "payload", "backdoor", "trojan", "virus", "malware",
            "keylog", "rootkit", "reverse", "bind", "nc.exe"
        };

        std::string memory_str(memory_data.begin(), memory_data.end());
        
        for (const auto& keyword : suspicious_keywords) {
            std::regex pattern(keyword, std::regex_constants::icase);
            std::sregex_iterator iter(memory_str.begin(), memory_str.end(), pattern);
            std::sregex_iterator end;

            for (; iter != end; ++iter) {
                std::smatch match = *iter;
                std::string context = extractContext(match.position(), 50);
                suspicious_strings.push_back(keyword + " at offset " + 
                    std::to_string(match.position()) + ": " + context);
            }
        }

        std::cout << "Found " << suspicious_strings.size() << " suspicious strings" << std::endl;
    }

    void extractStrings(size_t min_length = 4) {
        std::vector<std::string> ascii_strings;
        std::vector<std::string> unicode_strings;

        // Extract ASCII strings
        std::string current_string;
        for (size_t i = 0; i < memory_data.size(); i++) {
            uint8_t byte = memory_data[i];
            if (byte >= 32 && byte <= 126) {  // Printable ASCII
                current_string += static_cast<char>(byte);
            } else {
                if (current_string.length() >= min_length) {
                    ascii_strings.push_back(current_string);
                }
                current_string.clear();
            }
        }

        // Extract Unicode strings (simplified - looking for UTF-16LE)
        for (size_t i = 0; i < memory_data.size() - 1; i += 2) {
            if (memory_data[i] >= 32 && memory_data[i] <= 126 && memory_data[i + 1] == 0) {
                std::string unicode_str;
                size_t j = i;
                while (j < memory_data.size() - 1 && 
                       memory_data[j] >= 32 && memory_data[j] <= 126 && 
                       memory_data[j + 1] == 0) {
                    unicode_str += static_cast<char>(memory_data[j]);
                    j += 2;
                }
                if (unicode_str.length() >= min_length) {
                    unicode_strings.push_back(unicode_str);
                    i = j;
                }
            }
        }

        std::cout << "Extracted " << ascii_strings.size() << " ASCII strings" << std::endl;
        std::cout << "Extracted " << unicode_strings.size() << " Unicode strings" << std::endl;
    }

    void analyzeHeap() {
        // Look for heap structures and allocations
        const uint8_t heap_signature[] = {0xEE, 0xFE, 0xEE, 0xFE};  // Common heap pattern
        
        size_t heap_count = 0;
        for (size_t i = 0; i < memory_data.size() - 4; i++) {
            if (std::memcmp(&memory_data[i], heap_signature, 4) == 0) {
                heap_count++;
            }
        }

        std::cout << "Found " << heap_count << " potential heap structures" << std::endl;
    }

    void generateReport() {
        std::cout << "\n=== Memory Forensics Report ===" << std::endl;
        std::cout << "Memory dump size: " << memory_data.size() << " bytes" << std::endl;
        
        std::cout << "\n--- Process Information ---" << std::endl;
        for (const auto& proc : processes) {
            std::cout << "Process: " << proc.name 
                      << " (PID: " << proc.pid 
                      << ", PPID: " << proc.ppid 
                      << ") at offset 0x" << std::hex << proc.offset << std::dec << std::endl;
        }

        std::cout << "\n--- Network Artifacts ---" << std::endl;
        for (const auto& conn : connections) {
            std::cout << "IP: " << conn.local_addr 
                      << " at offset 0x" << std::hex << conn.offset << std::dec << std::endl;
        }

        std::cout << "\n--- Suspicious Strings ---" << std::endl;
        for (const auto& str : suspicious_strings) {
            std::cout << str << std::endl;
        }
    }

private:
    size_t findBytes(const std::string& pattern, size_t start_pos = 0) {
        if (start_pos >= memory_data.size()) return std::string::npos;
        
        auto it = std::search(memory_data.begin() + start_pos, memory_data.end(),
                             pattern.begin(), pattern.end());
        
        if (it != memory_data.end()) {
            return std::distance(memory_data.begin(), it);
        }
        return std::string::npos;
    }

    uint32_t extractDword(size_t offset) {
        if (offset + 4 > memory_data.size()) return 0;
        
        return *reinterpret_cast<const uint32_t*>(&memory_data[offset]);
    }

    bool isValidIP(const std::string& ip) {
        std::regex ip_pattern(R"(^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$)");
        std::smatch match;
        
        if (std::regex_match(ip, match, ip_pattern)) {
            for (int i = 1; i <= 4; i++) {
                int octet = std::stoi(match[i].str());
                if (octet < 0 || octet > 255) return false;
            }
            return true;
        }
        return false;
    }

    std::string extractContext(size_t offset, size_t context_size) {
        size_t start = (offset < context_size) ? 0 : offset - context_size;
        size_t end = std::min(memory_data.size(), offset + context_size);
        
        std::string context;
        for (size_t i = start; i < end; i++) {
            char c = static_cast<char>(memory_data[i]);
            if (c >= 32 && c <= 126) {
                context += c;
            } else {
                context += '.';
            }
        }
        return context;
    }
};

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <memory_dump_file>" << std::endl;
        return 1;
    }

    MemoryForensics analyzer;
    
    if (!analyzer.loadMemoryDump(argv[1])) {
        return 1;
    }

    std::cout << "Starting memory analysis..." << std::endl;
    
    analyzer.findProcessStructures();
    analyzer.findNetworkArtifacts();
    analyzer.findSuspiciousStrings();
    analyzer.extractStrings();
    analyzer.analyzeHeap();
    
    analyzer.generateReport();

    return 0;
}
