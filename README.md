# High-Performance Big Data Log Parser

A data pipeline that processes 5M+ Apache server log entries using
memory-mapped I/O in C++, persists results to SQLite, and performs
security and traffic analysis in Python — parsing 800MB at 200+ MB/sec.

---

## Architecture
```
gen_logs.py  (Python)
    ├── 1,000+ unique IPs across public and private ranges
    ├── Realistic status code distribution (85% 200, 3% 404, 0.5% 500)
    ├── Apache combined log format with user agents and referrers
    ├── Timestamps spread across 30-day window
    └── access.log  (5M+ lines, ~800MB)

parser.cpp  (C++)
    ├── mmap() — file mapped directly into virtual memory
    ├── madvise(MADV_SEQUENTIAL) — kernel prefetch hint
    ├── Pointer-based parsing — zero std::string per line
    ├── Multi-threaded — splits at newline boundaries
    ├── Configurable status codes via -s flag
    ├── Timing metrics — MB/sec and lines/sec reported
    └── parsed_errors.csv / parsed_status.csv / parsed_ips.csv /
        parsed_top_attackers.csv

analyzer.py  (Python)
    ├── SQLite persistence with indexes on ip, status, timestamp
    ├── Threat scoring — error_rate × √(total_requests) × 100
    ├── Attack pattern detection — DDoS, scanners, brute force
    ├── Temporal analysis — hourly error distribution
    ├── Resource analysis — top problematic endpoints
    └── log_analysis_report.html  (full report with recommendations)

run_pipeline.sh  (Bash)
    └── End-to-end orchestration with timing and error handling
```

**Stack:** C++17 · Pthreads · mmap · SQLite · Python · Pandas · Matplotlib · Seaborn

---

## Performance design

**Memory-mapped I/O** — the file is mapped into virtual address space
with `mmap()` and `madvise(MADV_SEQUENTIAL)`, letting the kernel prefetch
pages ahead of the scan and eliminating explicit `read()` syscalls.

**Zero-copy parsing** — each line is parsed using raw pointer arithmetic.
IP, resource, and status code are extracted by scanning forward through
mapped memory without constructing any intermediate strings.

**Multi-threaded execution** — the mapped region is divided into N chunks
at newline boundaries, one per hardware thread. Each thread accumulates
results in a local `ParseResult` struct. A single merge pass combines
results after joining — no mutex contention during parsing.

---

## Getting started
```bash
pip install pandas numpy matplotlib seaborn
```

**Automated (recommended)**
```bash
chmod +x run_pipeline.sh
./run_pipeline.sh              # default: 5M lines
./run_pipeline.sh 1000000      # custom line count
```

**Manual**
```bash
python3 gen_logs.py -n 5000000 -o access.log
g++ -std=c++17 -O3 -march=native -flto -pthread parser.cpp -o parser
./parser -i access.log -o parsed -s 404,500,403,401 -t $(nproc)
python3 analyzer.py -e parsed_errors.csv -s parsed_status.csv -i parsed_ips.csv
```

**Parser flags**

| Flag | Description | Default |
|---|---|---|
| `-i` | Input log file | `access.log` |
| `-o` | Output file prefix | `parsed` |
| `-s` | Status codes to extract | `404,500,403,401` |
| `-t` | Thread count | hardware concurrency |
| `-v` | Verbose output | off |

---

## Sample output
```
Input file: access.log
Target statuses: 404,500,403,401
Threads: 8

File size: 823.42 MB
Total lines: 5,000,000
Error lines: 247,831
Parse time: 3.84 seconds
Processing speed: 214.43 MB/sec
Lines/sec: 1,302,083

HTTP 200: 4,250,000 (85.00%)
HTTP 404:   150,000  (3.00%)
HTTP 500:    25,000  (0.50%)
```

---

## Analysis outputs
```
status_distribution.png    →  HTTP status code breakdown
top_attackers.png          →  Top 15 IPs by threat score
temporal_analysis.png      →  Hourly error distribution
resource_analysis.png      →  Top 15 most targeted endpoints
log_analysis_report.html   →  Full report with recommendations
```

Threat scoring: `error_rate × √(total_requests) × 100`
IPs classified HIGH (>20% error rate), MEDIUM (>10%), or LOW.
