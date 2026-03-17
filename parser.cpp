#include <iostream>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <chrono>
#include <vector>
#include <unordered_map>
#include <fstream>
#include <iomanip>
#include <thread>
#include <atomic>
#include <getopt.h>

struct ParseResult {
    std::unordered_map<std::string, std::vector<std::string>> errors;  // IP -> list of resources
    std::unordered_map<int, int> status_counts;  // status code -> count
    std::unordered_map<std::string, int> ip_counts;  // IP -> total requests
    long long total_lines = 0;
    long long error_lines = 0;
    long long skipped_comments = 0;
    double parse_time = 0;
    size_t file_size = 0;
};

class LogParser {
private:
    const char* filepath;
    std::vector<int> target_statuses;
    bool verbose;
    int num_threads;
    
    // Thread-local storage for parallel parsing
    struct ThreadData {
        ParseResult result;
        size_t start;
        size_t end;
    };
    
public:
    LogParser(const char* path, const std::vector<int>& statuses, bool v = false, int threads = 4)
        : filepath(path), target_statuses(statuses), verbose(v), num_threads(threads) {}
    
    bool is_comment(const char* line_start, const char* line_end) {
        // Skip empty lines
        if (line_start >= line_end) return true;
        
        // Check if first non-space character is '#'
        const char* p = line_start;
        while (p < line_end && (*p == ' ' || *p == '\t')) p++;
        if (p < line_end && *p == '#') return true;
        
        return false;
    }
    
    bool parse_line(const char* start, const char* end, ParseResult& result) {
        // Skip empty lines
        if (start >= end) return false;
        
        // Skip comments
        if (is_comment(start, end)) {
            result.skipped_comments++;
            return false;
        }
        
        result.total_lines++;
        
        // Fast parsing using pointer arithmetic (no std::string copies)
        const char* p = start;
        
        // Extract IP (up to first space)
        const char* ip_start = p;
        while (p < end && *p != ' ') p++;
        if (p >= end) return false;
        
        std::string ip(ip_start, p - ip_start);
        
        // Skip to timestamp section
        int space_count = 0;
        while (p < end && space_count < 3) {
            if (*p == ' ') space_count++;
            p++;
        }
        if (p >= end) return false;
        
        // Skip timestamp
        while (p < end && *p != '"') p++;
        if (p >= end) return false;
        p++; // Skip the opening quote
        
        // Now parse the request: "GET /resource HTTP/1.1"
        // Skip method (GET/POST etc)
        while (p < end && *p != ' ') p++;
        if (p >= end) return false;
        p++; // Skip space
        
        // Extract resource (between method and HTTP version)
        const char* resource_start = p;
        while (p < end && *p != ' ') p++;
        if (p >= end) return false;
        
        std::string resource(resource_start, p - resource_start);
        
        // Skip HTTP version
        while (p < end && *p != '"') p++;
        if (p >= end) return false;
        p++; // Skip closing quote
        
        // Skip to status code
        while (p < end && *p == ' ') p++;
        
        // Parse status code
        if (p + 3 <= end) {
            int status = 0;
            for (int i = 0; i < 3; i++) {
                if (p[i] < '0' || p[i] > '9') break;
                status = status * 10 + (p[i] - '0');
            }
            
            result.status_counts[status]++;
            result.ip_counts[ip]++;  // Count request for this IP
            
            // Check if this is a target status
            for (int target : target_statuses) {
                if (status == target) {
                    result.error_lines++;
                    result.errors[ip].push_back(resource);
                    break;
                }
            }
        }
        
        return true;
    }
    
    void parse_range(const char* addr, size_t start, size_t end, ParseResult& result) {
        const char* p = addr + start;
        const char* line_start = p;
        
        while (p < addr + end) {
            if (*p == '\n') {
                parse_line(line_start, p, result);
                line_start = p + 1;
            }
            p++;
        }
        
        // Handle last line if no newline at end
        if (line_start < addr + end) {
            parse_line(line_start, addr + end, result);
        }
    }
    
    ParseResult parse() {
        ParseResult result;
        result.file_size = 0;
        
        // Open file
        int fd = open(filepath, O_RDONLY);
        if (fd == -1) {
            std::cerr << "Error: Cannot open file " << filepath << std::endl;
            return result;
        }
        
        // Get file size
        struct stat sb;
        if (fstat(fd, &sb) == -1) {
            std::cerr << "Error: Cannot stat file" << std::endl;
            close(fd);
            return result;
        }
        
        result.file_size = sb.st_size;
        
        // Memory map the file
        char* addr = (char*)mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (addr == MAP_FAILED) {
            std::cerr << "Error: mmap failed" << std::endl;
            close(fd);
            return result;
        }
        
        // Advise kernel about sequential access pattern
        madvise(addr, sb.st_size, MADV_SEQUENTIAL);
        
        auto start_time = std::chrono::high_resolution_clock::now();
        
        if (num_threads <= 1) {
            // Single-threaded parsing
            parse_range(addr, 0, sb.st_size, result);
        } else {
            // Multi-threaded parsing
            std::vector<std::thread> threads;
            std::vector<ThreadData> thread_data(num_threads);
            
            // Find good split points (at newlines)
            std::vector<size_t> split_points;
            split_points.push_back(0);
            
            size_t chunk_size = sb.st_size / num_threads;
            for (int i = 1; i < num_threads; i++) {
                size_t target = i * chunk_size;
                
                // Find next newline after target
                while (target < sb.st_size && addr[target] != '\n') {
                    target++;
                }
                if (target < sb.st_size) {
                    split_points.push_back(target + 1);
                }
            }
            split_points.push_back(sb.st_size);
            
            // Launch threads
            for (int i = 0; i < num_threads; i++) {
                if (i < split_points.size() - 1) {
                    thread_data[i].start = split_points[i];
                    thread_data[i].end = split_points[i + 1];
                    
                    threads.emplace_back(&LogParser::parse_range, this, 
                                         addr, thread_data[i].start, thread_data[i].end,
                                         std::ref(thread_data[i].result));
                }
            }
            
            // Join threads
            for (auto& t : threads) {
                t.join();
            }
            
            // Merge results
            for (int i = 0; i < num_threads; i++) {
                result.total_lines += thread_data[i].result.total_lines;
                result.error_lines += thread_data[i].result.error_lines;
                result.skipped_comments += thread_data[i].result.skipped_comments;
                
                // Merge maps
                for (const auto& [status, count] : thread_data[i].result.status_counts) {
                    result.status_counts[status] += count;
                }
                
                for (const auto& [ip, count] : thread_data[i].result.ip_counts) {
                    result.ip_counts[ip] += count;
                }
                
                for (const auto& [ip, resources] : thread_data[i].result.errors) {
                    auto& target = result.errors[ip];
                    target.insert(target.end(), resources.begin(), resources.end());
                }
            }
        }
        
        auto end_time = std::chrono::high_resolution_clock::now();
        result.parse_time = std::chrono::duration<double>(end_time - start_time).count();
        
        // Cleanup
        munmap(addr, sb.st_size);
        close(fd);
        
        return result;
    }
    
    void write_results(const ParseResult& result, const std::string& output_prefix) {
        // Write error details
        std::ofstream error_file(output_prefix + "_errors.csv");
        error_file << "ip,resource,status\n";
        
        for (const auto& [ip, resources] : result.errors) {
            for (const auto& resource : resources) {
                // Determine which status code caused this error
                // For simplicity, we'll just use the first target status
                int status = target_statuses.empty() ? 404 : target_statuses[0];
                error_file << ip << "," << resource << "," << status << "\n";
            }
        }
        
        // Write status summary
        std::ofstream status_file(output_prefix + "_status.csv");
        status_file << "status_code,count\n";
        for (const auto& [status, count] : result.status_counts) {
            status_file << status << "," << count << "\n";
        }
        
        // Write IP summary with error rates pre-calculated
        std::ofstream ip_file(output_prefix + "_ips.csv");
        ip_file << "ip,total_requests,error_count,error_rate\n";
        
        for (const auto& [ip, count] : result.ip_counts) {
            auto it = result.errors.find(ip);
            int error_count = (it != result.errors.end()) ? it->second.size() : 0;
            double error_rate = (count > 0) ? (100.0 * error_count / count) : 0.0;
            ip_file << ip << "," << count << "," << error_count << "," 
                    << std::fixed << std::setprecision(2) << error_rate << "\n";
        }
        
        // Write top attackers
        std::ofstream top_file(output_prefix + "_top_attackers.csv");
        top_file << "ip,error_count,total_requests,error_rate\n";
        
        std::vector<std::pair<std::string, int>> attackers;
        for (const auto& [ip, resources] : result.errors) {
            attackers.emplace_back(ip, resources.size());
        }
        
        std::sort(attackers.begin(), attackers.end(), 
                  [](const auto& a, const auto& b) { return a.second > b.second; });
        
        for (size_t i = 0; i < std::min(attackers.size(), size_t(100)); i++) {
            const auto& [ip, error_count] = attackers[i];
            int total = result.ip_counts.at(ip);
            double rate = 100.0 * error_count / total;
            top_file << ip << "," << error_count << "," << total << "," 
                     << std::fixed << std::setprecision(2) << rate << "\n";
        }
    }
    
    void print_stats(const ParseResult& result) {
        std::cout << "\nPARSING STATISTICS\n";
        std::cout << "=====================\n";
        std::cout << "File size: " << result.file_size << " bytes (" 
                  << std::fixed << std::setprecision(2) 
                  << result.file_size / (1024.0 * 1024.0) << " MB)\n";
        std::cout << "Total lines: " << result.total_lines << "\n";
        std::cout << "Skipped comments: " << result.skipped_comments << "\n";
        std::cout << "Error lines (";
        for (size_t i = 0; i < target_statuses.size(); i++) {
            if (i > 0) std::cout << ",";
            std::cout << target_statuses[i];
        }
        std::cout << "): " << result.error_lines << "\n";
        std::cout << "Parse time: " << result.parse_time << " seconds\n";
        std::cout << "Processing speed: " 
                  << std::fixed << std::setprecision(2)
                  << (result.file_size / (1024.0 * 1024.0)) / result.parse_time 
                  << " MB/sec\n";
        std::cout << "Lines/sec: " << std::fixed << std::setprecision(0)
                  << result.total_lines / result.parse_time << "\n";
        
        std::cout << "\nSTATUS CODE DISTRIBUTION\n";
        std::cout << "===========================\n";
        std::vector<std::pair<int, int>> status_vec(result.status_counts.begin(), 
                                                    result.status_counts.end());
        std::sort(status_vec.begin(), status_vec.end());
        
        for (const auto& [status, count] : status_vec) {
            double pct = 100.0 * count / result.total_lines;
            std::cout << "HTTP " << status << ": " << count << " (" 
                      << std::fixed << std::setprecision(2) << pct << "%)\n";
            
            // Visual bar
            int bar_len = (int)(pct / 2);
            std::cout << "  [";
            for (int i = 0; i < 50; i++) {
                if (i < bar_len) std::cout << "#";
                else std::cout << " ";
            }
            std::cout << "]\n";
        }
        
        std::cout << "\nTOP ATTACKERS (by error count)\n";
        std::cout << "================================\n";
        
        std::vector<std::pair<std::string, int>> attackers;
        for (const auto& [ip, resources] : result.errors) {
            attackers.emplace_back(ip, resources.size());
        }
        
        std::sort(attackers.begin(), attackers.end(), 
                  [](const auto& a, const auto& b) { return a.second > b.second; });
        
        for (size_t i = 0; i < std::min(attackers.size(), size_t(10)); i++) {
            const auto& [ip, error_count] = attackers[i];
            int total = result.ip_counts.at(ip);
            double rate = 100.0 * error_count / total;
            std::cout << (i+1) << ". " << ip << ": " << error_count << " errors, "
                      << total << " total requests, " 
                      << std::fixed << std::setprecision(1) << rate << "% error rate\n";
        }
    }
};

int main(int argc, char** argv) {
    std::string input_file = "access.log";
    std::string output_prefix = "parsed";
    std::vector<int> status_codes = {404, 500, 403, 401};  // Default error codes
    bool verbose = false;
    int threads = std::thread::hardware_concurrency();
    
    // Parse command line arguments
    int opt;
    while ((opt = getopt(argc, argv, "i:o:s:vt:")) != -1) {
        switch (opt) {
            case 'i':
                input_file = optarg;
                break;
            case 'o':
                output_prefix = optarg;
                break;
            case 's':
                status_codes.clear();
                char* token = strtok(optarg, ",");
                while (token) {
                    status_codes.push_back(atoi(token));
                    token = strtok(NULL, ",");
                }
                break;
            case 'v':
                verbose = true;
                break;
            case 't':
                threads = atoi(optarg);
                break;
            default:
                std::cerr << "Usage: " << argv[0] 
                          << " [-i input_file] [-o output_prefix] [-s status_codes] [-t threads] [-v]\n";
                return 1;
        }
    }
    
    std::cout << "High-Performance Log Parser\n";
    std::cout << "==============================\n";
    std::cout << "Input file: " << input_file << "\n";
    std::cout << "Target statuses: ";
    for (size_t i = 0; i < status_codes.size(); i++) {
        if (i > 0) std::cout << ",";
        std::cout << status_codes[i];
    }
    std::cout << "\n";
    std::cout << "Threads: " << threads << "\n\n";
    
    LogParser parser(input_file.c_str(), status_codes, verbose, threads);
    ParseResult result = parser.parse();
    
    if (result.total_lines > 0) {
        parser.print_stats(result);
        parser.write_results(result, output_prefix);
        std::cout << "\n✅ Results written to " << output_prefix << "_*.csv\n";
    } else {
        std::cerr << "❌ Parsing failed or no data found\n";
        return 1;
    }
    
    return 0;
}
