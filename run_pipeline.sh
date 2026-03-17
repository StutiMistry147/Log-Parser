#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   HIGH-PERFORMANCE BIG DATA LOG PIPELINE                ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"

# Configuration
LINES=${1:-5000000}
THREADS=$(nproc)

echo -e "\n${YELLOW}Configuration${NC}"
echo "  Lines to generate: $(printf "%'d" $LINES)"
echo "  CPU Threads: $THREADS"
echo "  Date: $(date)"

# Step 1: Generate logs
echo -e "\n${YELLOW}[1/4] Generating synthetic logs...${NC}"
time python3 gen_logs.py -n $LINES -o access.log

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Log generation failed${NC}"
    exit 1
fi

# Step 2: Compile parser
echo -e "\n${YELLOW}[2/4] Compiling high-performance parser...${NC}"
g++ -std=c++17 -O3 -march=native -flto -pthread parser.cpp -o parser

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Compilation failed${NC}"
    exit 1
fi

# Step 3: Run parser
echo -e "\n${YELLOW}[3/4] Running parser (mmap + parallel processing)...${NC}"
time ./parser -i access.log -o parsed -s 404,500,403,401 -t $THREADS

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Parsing failed${NC}"
    exit 1
fi

# Step 4: Run analysis
echo -e "\n${YELLOW}[4/4] Running comprehensive analysis...${NC}"
time python3 analyzer.py -e parsed_errors.csv -s parsed_status.csv -i parsed_ips.csv

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Analysis failed${NC}"
    exit 1
fi

# Performance summary - FIXED: No header line to subtract
echo -e "\n${GREEN}✅ PIPELINE COMPLETE${NC}"
echo -e "\n${BLUE} Performance Summary${NC}"
echo "  Generated: $(wc -l < access.log | xargs printf "%'d") lines (no header)"
echo "  File size: $(ls -lh access.log | awk '{print $5}')"
echo "  Errors found: $(wc -l < parsed_errors.csv 2>/dev/null | xargs printf "%'d" 2>/dev/null || echo "0")"
echo "  Output files:"
echo "    - parsed_errors.csv (error details)"
echo "    - parsed_status.csv (status distribution)"
echo "    - parsed_ips.csv (IP statistics)"
echo "    - parsed_top_attackers.csv (threat analysis)"
echo "    - *.png (visualizations)"
echo "    - log_analysis_report.html (complete report)"

# Check if report was generated
if [ -f "log_analysis_report.html" ]; then
    # Optional: Open report in browser
    if command -v xdg-open > /dev/null; then
        xdg-open log_analysis_report.html 2>/dev/null &
    elif command -v open > /dev/null; then
        open log_analysis_report.html 2>/dev/null &
    fi
    echo -e "\n${GREEN}✨ Report generated: log_analysis_report.html${NC}"
else
    echo -e "\n${RED}⚠ Report generation failed${NC}"
fi

echo -e "\n${GREEN}✨ Pipeline execution complete!${NC}"
