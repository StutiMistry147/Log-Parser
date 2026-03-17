#!/usr/bin/env python3
"""
Realistic Apache log generator with proper distributions and progress tracking
"""

import random
import time
import argparse
from datetime import datetime, timedelta
import sys

class ApacheLogGenerator:
    def __init__(self):
        # Expand IP pool to 1000+ realistic IPs
        self.ips = self.generate_ip_pool(1000)
        
        # Realistic HTTP methods with weights
        self.methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]
        self.method_weights = [0.7, 0.15, 0.05, 0.03, 0.05, 0.02]  # 70% GET
        
        # Realistic resources with hot spots
        self.resources = {
            # Hot paths (frequently accessed)
            "/index.html": 0.25,
            "/api/users": 0.15,
            "/api/login": 0.10,
            "/css/style.css": 0.08,
            "/js/app.js": 0.08,
            "/images/logo.png": 0.05,
            
            # Admin paths (rare)
            "/admin": 0.01,
            "/admin/users": 0.005,
            "/api/admin/stats": 0.005,
            
            # API endpoints
            "/api/products": 0.08,
            "/api/orders": 0.06,
            "/api/search": 0.04,
            
            # Old paths (very rare)
            "/old/index.html": 0.002,
            "/legacy/api": 0.003,
            
            # Potential attack targets
            "/wp-admin": 0.001,
            "/.env": 0.0005,
            "/phpmyadmin": 0.0005,
            "/api/v1/../": 0.001,  # Path traversal attempt
        }
        
        # Status codes with realistic weights
        self.status_codes = {
            200: 0.85,  # OK
            301: 0.03,  # Moved Permanently
            302: 0.02,  # Found
            304: 0.02,  # Not Modified
            400: 0.01,  # Bad Request
            401: 0.005, # Unauthorized
            403: 0.005, # Forbidden
            404: 0.03,  # Not Found
            500: 0.005, # Internal Server Error
            502: 0.002, # Bad Gateway
            503: 0.001, # Service Unavailable
        }
        
        # User agents (realistic list)
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15",
            "Mozilla/5.0 (iPad; CPU OS 14_0 like Mac OS X) AppleWebKit/605.1.15",
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
            "curl/7.68.0",
            "python-requests/2.25.1",
            "PostmanRuntime/7.26.8",
        ]
        
        # Referrers
        self.referrers = [
            "-",
            "https://www.google.com/",
            "https://www.bing.com/",
            "https://www.example.com/",
            "https://www.example.com/products",
            "https://www.example.com/about",
            "http://localhost:3000/",
            "https://mail.google.com/",
        ]
        
    def generate_ip_pool(self, count):
        """Generate realistic IP addresses across different ranges"""
        ips = []
        
        for i in range(count):
            if i < 50:
                # Private IPs
                ips.append(f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}")
            elif i < 150:
                # More private IPs
                ips.append(f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}")
            elif i < 200:
                # Private IPs
                ips.append(f"172.{random.randint(16, 31)}.{random.randint(0, 255)}.{random.randint(1, 254)}")
            else:
                # Public IPs
                ips.append(f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}")
        
        # Add some "attacker" IPs that appear more frequently
        attacker_ips = [
            "45.155.205.233",  # Known scanner
            "185.202.0.111",   # Botnet
            "103.42.176.50",   # Attack source
            "91.240.118.77",   # Scanner
            "5.188.206.15",    # Attacker
        ]
        ips.extend(attacker_ips * 3)  # Multiply to increase frequency
        
        random.shuffle(ips)
        return ips
    
    def generate_log_line(self, base_time):
        """Generate a single Apache log line"""
        ip = random.choice(self.ips)
        
        # Random time within 1 second of base
        log_time = base_time + timedelta(milliseconds=random.randint(0, 999))
        timestamp = log_time.strftime("%d/%b/%Y:%H:%M:%S +0000")
        
        # Weighted method selection
        method = random.choices(self.methods, weights=self.method_weights)[0]
        
        # Weighted resource selection
        resource = random.choices(
            list(self.resources.keys()), 
            weights=list(self.resources.values())
        )[0]
        
        # Weighted status code
        status = random.choices(
            list(self.status_codes.keys()),
            weights=list(self.status_codes.values())
        )[0]
        
        # Response size based on status and resource
        if status >= 400:
            size = random.randint(200, 1000)  # Error pages are smaller
        elif resource.endswith(('.png', '.jpg', '.gif')):
            size = random.randint(5000, 50000)  # Images are larger
        elif resource.endswith(('.css', '.js')):
            size = random.randint(1000, 10000)  # Static assets medium
        else:
            size = random.randint(500, 5000)    # HTML pages variable
        
        user_agent = random.choice(self.user_agents)
        referrer = random.choice(self.referrers)
        
        # Combine into Apache combined log format (NO COMMENT LINE)
        line = f'{ip} - - [{timestamp}] "{method} {resource} HTTP/1.1" {status} {size} "{referrer}" "{user_agent}"\n'
        
        return line
    
    def generate_logs(self, num_lines, output_file, show_progress=True):
        """Generate log file with progress tracking"""
        start_time = time.time()
        
        with open(output_file, 'w') as f:
            # NO HEADER COMMENT - just start with actual log lines
            # Base time: start 30 days ago and move forward
            base_time = datetime.now() - timedelta(days=30)
            time_increment = timedelta(seconds=30 * 24 * 60 * 60 / num_lines)  # Spread over 30 days
            
            for i in range(num_lines):
                line = self.generate_log_line(base_time)
                f.write(line)
                
                base_time += time_increment
                
                # Progress indicator
                if show_progress and (i + 1) % 100000 == 0:
                    elapsed = time.time() - start_time
                    rate = (i + 1) / elapsed
                    pct = (i + 1) / num_lines * 100
                    eta = (num_lines - (i + 1)) / rate if rate > 0 else 0
                    print(f"\rProgress: {pct:.1f}% ({i+1:,}/{num_lines:,} lines) | "
                          f"Rate: {rate:.0f} lines/sec | ETA: {eta:.0f}s", end='', flush=True)
        
        elapsed = time.time() - start_time
        print(f"\n✅ Generated {num_lines:,} lines in {elapsed:.2f} seconds")
        print(f"📁 Output file: {output_file}")
        print(f"⚡ Average speed: {num_lines/elapsed:.0f} lines/sec")
        
        # Print statistics
        self.print_statistics(output_file)
    
    def print_statistics(self, output_file):
        """Print quick statistics about generated file"""
        print("\n📊 File Statistics:")
        
        # Count lines
        with open(output_file, 'rb') as f:
            line_count = sum(1 for _ in f)
        
        # Get file size
        import os
        file_size = os.path.getsize(output_file)
        
        print(f"  - Total lines: {line_count:,}")
        print(f"  - File size: {file_size:,} bytes ({file_size/1024/1024:.2f} MB)")

def main():
    parser = argparse.ArgumentParser(description='Generate realistic Apache access logs')
    parser.add_argument('-n', '--num-lines', type=int, default=5000000,
                       help='Number of log lines to generate (default: 5,000,000)')
    parser.add_argument('-o', '--output', default='access.log',
                       help='Output file name (default: access.log)')
    parser.add_argument('--no-progress', action='store_true',
                       help='Disable progress indicator')
    
    args = parser.parse_args()
    
    print("🚀 Apache Log Generator")
    print("=======================")
    print(f"Lines to generate: {args.num_lines:,}")
    print(f"Output file: {args.output}")
    print()
    
    generator = ApacheLogGenerator()
    generator.generate_logs(args.num_lines, args.output, not args.no_progress)

if __name__ == "__main__":
    main()
