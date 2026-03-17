# High-Performance Big Data Log Parser

A high-speed data pipeline that processes 5M+ Apache server log
entries using memory-mapped I/O in C++, persists results to SQLite,
and performs comprehensive security and traffic analysis in Python.

---

## Overview

The pipeline demonstrates the "right tool for the right job"
philosophy in Big Data engineering. A C++ engine memory-maps the
log file directly into virtual address space and scans it using
pointer arithmetic with zero per-line heap allocation. Multi-threaded
parsing splits the file across CPU cores at newline boundaries.
Python then performs statistical threat analysis, temporal pattern
detection, and resource profiling on the extracted data.

---

## Architecture
```
gen_logs.py  (Python)
    ├── 1,000+ unique IPs across public and private ranges
    ├── Realistic status code distribution (85% 200, 3% 404, 0.5% 500)
    ├── Hotspot resource access patterns
    ├── Apache combined log format with user agents and referrers
    ├── Timestamps spread across 30-day window
    └── access.log  (5M+ lines, ~800MB)

parser.cpp  (C++)
    ├── mmap() — file mapped directly into virtual memory
    ├── madvise(MADV_SEQUENTIAL) — kernel prefetch hint
    ├── Pointer-based parsing — zero std::string per line
    ├── Multi-threaded — splits at newline boundaries
    ├── Comment skipping — ignores # lines
    ├── Configurable status codes via -s flag
    ├── Timing metrics — MB/sec and lines/sec reported
    └── parsed_errors.csv
        parsed_status.csv
        parsed_ips.csv  (with pre-calculated error_rate)
        parsed_top_attackers.csv

analyzer.py  (Python)
    ├── SQLite persistence with indexes on ip, status, timestamp
    ├── Threat scoring — error_rate × √(total_requests) × 100
    ├── Attack pattern detection — DDoS, scanners, brute force
    ├── Temporal analysis — hourly error distribution
    ├── Resource analysis — top problematic endpoints
    ├── 4-panel visualization dashboard
    └── log_analysis_report.html  (full HTML report with recommendations)

run_pipeline.sh  (Bash)
    └── End-to-end orchestration with timing and error handling
```

---

## Tech Stack

| Component | Technology |
|---|---|
| Log Generator | Python (weighted random distributions) |
| Parser Engine | C++ (mmap, madvise, Pthreads) |
| Data Persistence | SQLite (indexed) |
| Analysis | Python, Pandas, NumPy |
| Visualization | Matplotlib, Seaborn |

---

## Performance Design

**Memory-mapped I/O**

The file is mapped into virtual address space with `mmap()` and
`madvise(MADV_SEQUENTIAL)`. The kernel prefetches pages ahead of
the scan, eliminating explicit read() calls and reducing syscall
overhead.

**Zero-copy parsing**

Each line is parsed using raw pointer arithmetic. IP, resource,
and status code are extracted by scanning forward through the
mapped memory without constructing any intermediate strings until
the final output write.

**Multi-threaded execution**

The mapped region is divided into N chunks at newline boundaries,
one per hardware thread. Each thread accumulates results in a
local `ParseResult` struct. A single merge pass combines all
thread results after joining — no mutex contention during parsing.

---

## Getting Started

### Prerequisites

- GCC / G++ (C++17 or later)
- Python 3.8+
- SQLite3
```bash
pip install pandas numpy matplotlib seaborn
```

---

## Running the Pipeline

### Option 1 — Automated (recommended)
```bash
chmod +x run_pipeline.sh
./run_pipeline.sh              # default: 5M lines
./run_pipeline.sh 1000000      # custom: 1M lines
```

### Option 2 — Manual step by step
```bash
# Step 1: Generate logs
python3 gen_logs.py -n 5000000 -o access.log

# Step 2: Compile parser
g++ -std=c++17 -O3 -march=native -flto -pthread parser.cpp -o parser

# Step 3: Parse logs
./parser -i access.log -o parsed -s 404,500,403,401 -t $(nproc)

# Step 4: Analyze
python3 analyzer.py -e parsed_errors.csv -s parsed_status.csv -i parsed_ips.csv
```

### Parser flags

| Flag | Description | Default |
|---|---|---|
| `-i` | Input log file | `access.log` |
| `-o` | Output file prefix | `parsed` |
| `-s` | Comma-separated status codes to extract | `404,500,403,401` |
| `-t` | Thread count | hardware concurrency |
| `-v` | Verbose output | off |

---

## Sample Output
```
🚀 High-Performance Log Parser
==============================
Input file: access.log
Target statuses: 404,500,403,401
Threads: 8

📊 PARSING STATISTICS
=====================
File size: 823.42 MB
Total lines: 5,000,000
Skipped comments: 0
Error lines: 247,831
Parse time: 3.84 seconds
Processing speed: 214.43 MB/sec
Lines/sec: 1,302,083

📈 STATUS CODE DISTRIBUTION
===========================
HTTP 200: 4,250,000 (85.00%)
  [#############################################     ]
HTTP 404: 150,000 (3.00%)
  [#                                                 ]
HTTP 500: 25,000 (0.50%)
  [                                                  ]
```

---

## Analysis Output

The analyzer produces four PNG charts and one HTML report:
```
status_distribution.png    →  HTTP status code breakdown
top_attackers.png          →  Top 15 IPs by error count with threat level
temporal_analysis.png      →  Hourly error distribution
resource_analysis.png      →  Top 15 most targeted endpoints
log_analysis_report.html   →  Full report with threat table and recommendations
```

**Threat scoring formula:**
```
threat_score = error_rate × √(total_requests) × 100
```

IPs are classified HIGH (>20% error rate), MEDIUM (>10%), or LOW.

---

## Project Structure
```
big-data-log-parser/
├── gen_logs.py              # Realistic Apache log generator
├── parser.cpp               # C++ mmap multi-threaded parser
├── analyzer.py              # Python threat analysis engine
├── run_pipeline.sh          # End-to-end pipeline script
├── access.log               # Generated log file (auto-created)
├── parsed_errors.csv        # Extracted error records (auto-created)
├── parsed_status.csv        # Status code summary (auto-created)
├── parsed_ips.csv           # IP statistics with error rates (auto-created)
├── parsed_top_attackers.csv # Top 100 threat sources (auto-created)
├── logs.db                  # SQLite database (auto-created)
├── *.png                    # Visualization outputs (auto-created)
├── log_analysis_report.html # HTML report (auto-created)
└── README.md
```

---
