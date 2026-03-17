#!/usr/bin/env python3
"""
Big Data Log Analyzer - Comprehensive log analysis with SQLite and visualization
"""

import pandas as pd
import sqlite3
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from datetime import datetime
import argparse
import os
import warnings
warnings.filterwarnings('ignore')

class LogAnalyzer:
    def __init__(self, db_path='logs.db'):
        self.conn = sqlite3.connect(db_path)
        self.errors_df = pd.DataFrame()
        self.status_df = pd.DataFrame()
        self.ips_df = pd.DataFrame()
        self.setup_database()
        
    def setup_database(self):
        """Create database schema"""
        cursor = self.conn.cursor()
        
        # Main logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                timestamp TEXT,
                method TEXT,
                resource TEXT,
                status INTEGER,
                size INTEGER,
                referrer TEXT,
                user_agent TEXT,
                parsed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip ON logs(ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_status ON logs(status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON logs(timestamp)')
        
        # Summary table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS daily_summary (
                date TEXT PRIMARY KEY,
                total_requests INTEGER,
                unique_ips INTEGER,
                error_count INTEGER,
                avg_response_size REAL
            )
        ''')
        
        self.conn.commit()
    
    def load_parsed_data(self, error_file='parsed_errors.csv', 
                         status_file='parsed_status.csv',
                         ip_file='parsed_ips.csv'):
        """Load data from parser output"""
        print("📥 Loading parsed data...")
        
        # Load error details
        if os.path.exists(error_file):
            self.errors_df = pd.read_csv(error_file)
            print(f"  - Errors: {len(self.errors_df):,} records")
        else:
            self.errors_df = pd.DataFrame()
            print("  ⚠ No error file found")
        
        # Load status summary
        if os.path.exists(status_file):
            self.status_df = pd.read_csv(status_file)
            print(f"  - Status codes: {len(self.status_df)} unique")
        else:
            self.status_df = pd.DataFrame()
        
        # Load IP summary
        if os.path.exists(ip_file):
            self.ips_df = pd.read_csv(ip_file)
            print(f"  - IPs: {len(self.ips_df):,} unique")
            
            # Ensure error_rate column exists
            if 'error_rate' not in self.ips_df.columns:
                if 'error_count' in self.ips_df.columns and 'total_requests' in self.ips_df.columns:
                    self.ips_df['error_rate'] = self.ips_df['error_count'] / self.ips_df['total_requests']
                else:
                    self.ips_df['error_rate'] = 0
        else:
            self.ips_df = pd.DataFrame()
    
    def analyze_threats(self):
        """Analyze potential security threats"""
        print("\n🔒 THREAT ANALYSIS")
        print("="*60)
        
        if self.ips_df.empty:
            print("No IP data available for threat analysis")
            return pd.DataFrame()
        
        # Ensure we have error_rate column
        if 'error_rate' not in self.ips_df.columns:
            if 'error_count' in self.ips_df.columns and 'total_requests' in self.ips_df.columns:
                self.ips_df['error_rate'] = self.ips_df['error_count'] / self.ips_df['total_requests']
            else:
                self.ips_df['error_rate'] = 0
        
        # Calculate threat score
        # Threat score = error_rate * sqrt(total_requests) * anomaly_factor
        self.ips_df['threat_score'] = (
            self.ips_df['error_rate'] * 
            np.sqrt(self.ips_df['total_requests']) *
            100  # Scale factor
        )
        
        # Identify potential threats
        threats = self.ips_df.nlargest(20, 'threat_score')
        
        print("\n🚨 TOP 20 POTENTIAL THREATS")
        print("-" * 80)
        print(f"{'IP':<20} {'Requests':<10} {'Errors':<8} {'Error Rate':<12} {'Threat Score':<12}")
        print("-" * 80)
        
        for _, row in threats.iterrows():
            print(f"{row['ip']:<20} {row['total_requests']:<10} "
                  f"{row['error_count'] if 'error_count' in row else 0:<8} "
                  f"{row['error_rate']:<11.1%} "
                  f"{row['threat_score']:<11.1f}")
        
        # Detect attack patterns
        print("\n📊 ATTACK PATTERN DETECTION")
        print("-" * 40)
        
        # Check for potential DDoS (high request volume)
        ddos_threshold = self.ips_df['total_requests'].quantile(0.99)
        potential_ddos = self.ips_df[self.ips_df['total_requests'] > ddos_threshold]
        print(f"Potential DDoS sources (>99th percentile): {len(potential_ddos)} IPs")
        
        # Check for scanners (high error rate)
        scanner_threshold = self.ips_df['error_rate'].quantile(0.95)
        potential_scanners = self.ips_df[self.ips_df['error_rate'] > scanner_threshold]
        print(f"Potential scanners (>95th percentile error rate): {len(potential_scanners)} IPs")
        
        # Check for brute force (repeated 401/403)
        if not self.errors_df.empty and 'status' in self.errors_df.columns:
            auth_errors = self.errors_df[self.errors_df['status'].isin([401, 403])]
            if not auth_errors.empty:
                brute_force = auth_errors['ip'].value_counts().head(10)
                print("\nPotential brute force attempts (auth failures):")
                for ip, count in brute_force.items():
                    print(f"  {ip}: {count} auth failures")
        
        return threats
    
    def analyze_temporal_patterns(self):
        """Analyze patterns over time"""
        print("\n⏰ TEMPORAL ANALYSIS")
        print("="*60)
        
        if self.errors_df.empty or 'timestamp' not in self.errors_df.columns:
            print("No timestamp data available")
            return
        
        # Parse timestamps (handle potential parsing errors)
        try:
            # Extract hour from timestamp string (format: DD/MMM/YYYY:HH:MM:SS)
            self.errors_df['hour'] = self.errors_df['timestamp'].str.extract(r':(\d{2}):').astype(int)
        except:
            print("Could not parse timestamps")
            return
        
        # Errors by hour
        hourly_errors = self.errors_df.groupby('hour').size()
        
        print("\n📈 Error Distribution by Hour")
        print("-" * 40)
        if not hourly_errors.empty:
            max_count = hourly_errors.max()
            for hour in range(24):
                count = hourly_errors.get(hour, 0)
                bar = '█' * int(count / max_count * 30) if max_count > 0 else ''
                print(f"{hour:02d}:00: {bar} ({count})")
            
            # Peak error times
            peak_hour = hourly_errors.idxmax()
            print(f"\nPeak error hour: {peak_hour:02d}:00 ({hourly_errors.max()} errors)")
        else:
            print("No hourly data available")
        
        # Create temporal plot
        fig, axes = plt.subplots(1, 2, figsize=(14, 5))
        
        if not hourly_errors.empty:
            # Hourly distribution
            axes[0].bar(hourly_errors.index, hourly_errors.values, color='red', alpha=0.7)
            axes[0].set_xlabel('Hour of Day')
            axes[0].set_ylabel('Number of Errors')
            axes[0].set_title('Error Distribution by Hour')
            axes[0].grid(True, alpha=0.3)
            axes[0].set_xticks(range(0, 24, 2))
            
            # Error rate trend
            if len(hourly_errors) > 1:
                axes[1].plot(hourly_errors.index, hourly_errors.values, 
                            marker='o', linestyle='-', color='blue')
                axes[1].fill_between(hourly_errors.index, hourly_errors.values, alpha=0.3)
                axes[1].set_xlabel('Hour of Day')
                axes[1].set_ylabel('Error Count')
                axes[1].set_title('Error Trend Throughout Day')
                axes[1].grid(True, alpha=0.3)
                axes[1].set_xticks(range(0, 24, 2))
        else:
            axes[0].text(0.5, 0.5, 'No temporal data available', 
                        ha='center', va='center', transform=axes[0].transAxes)
            axes[1].text(0.5, 0.5, 'No temporal data available', 
                        ha='center', va='center', transform=axes[1].transAxes)
        
        plt.tight_layout()
        plt.savefig('temporal_analysis.png', dpi=150, bbox_inches='tight')
        print("\n📊 Temporal analysis saved to 'temporal_analysis.png'")
    
    def analyze_resources(self):
        """Analyze problematic resources"""
        print("\n🌐 RESOURCE ANALYSIS")
        print("="*60)
        
        if self.errors_df.empty or 'resource' not in self.errors_df.columns:
            print("No resource data available")
            return
        
        # Top problematic resources
        top_resources = self.errors_df['resource'].value_counts().head(15)
        
        if top_resources.empty:
            print("No resource data available")
            return
        
        print("\n📄 TOP 15 PROBLEMATIC RESOURCES")
        print("-" * 60)
        for resource, count in top_resources.items():
            print(f"{count:6d}  {resource}")
        
        # Create resource plot
        plt.figure(figsize=(12, 6))
        colors = plt.cm.Reds(np.linspace(0.3, 1, len(top_resources)))
        bars = plt.barh(range(len(top_resources)), top_resources.values, color=colors[::-1])
        plt.yticks(range(len(top_resources)), [r[:50] + '...' if len(r) > 50 else r for r in top_resources.index])
        plt.xlabel('Number of Errors')
        plt.title('Most Problematic Resources')
        
        # Add value labels
        max_val = top_resources.max()
        for i, (bar, val) in enumerate(zip(bars, top_resources.values)):
            plt.text(val + max_val*0.01, i, f'{val}', 
                    va='center', fontweight='bold')
        
        plt.tight_layout()
        plt.savefig('resource_analysis.png', dpi=150, bbox_inches='tight')
        print("\n📊 Resource analysis saved to 'resource_analysis.png'")
    
    def generate_report(self):
        """Generate comprehensive HTML report"""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Big Data Log Analysis Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
                h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
                h2 { color: #34495e; margin-top: 30px; }
                .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 20px 0; }
                .stat-card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); text-align: center; }
                .stat-value { font-size: 32px; font-weight: bold; color: #3498db; }
                .stat-label { color: #7f8c8d; margin-top: 10px; }
                .stat-desc { font-size: 12px; color: #95a5a6; }
                .chart-container { background: white; padding: 20px; border-radius: 10px; margin: 20px 0; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
                table { width: 100%; border-collapse: collapse; background: white; border-radius: 10px; overflow: hidden; }
                th { background: #3498db; color: white; padding: 12px; }
                td { padding: 10px; border-bottom: 1px solid #ecf0f1; }
                tr:hover { background: #f8f9fa; }
                .threat-high { color: #e74c3c; font-weight: bold; }
                .threat-medium { color: #f39c12; font-weight: bold; }
                .threat-low { color: #27ae60; }
                .footer { margin-top: 40px; color: #95a5a6; text-align: center; font-size: 12px; }
            </style>
        </head>
        <body>
            <h1>📊 Big Data Log Analysis Report</h1>
            <p>Generated on """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>
        """
        
        # Summary statistics
        if not self.ips_df.empty:
            total_requests = self.ips_df['total_requests'].sum()
            unique_ips = len(self.ips_df)
            error_count = self.ips_df['error_count'].sum() if 'error_count' in self.ips_df.columns else 0
            error_rate = (error_count / total_requests * 100) if total_requests > 0 else 0
            
            html += f"""
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value">{total_requests:,}</div>
                    <div class="stat-label">Total Requests</div>
                    <div class="stat-desc">Processed logs</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{unique_ips:,}</div>
                    <div class="stat-label">Unique IPs</div>
                    <div class="stat-desc">Distinct visitors</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{error_count:,}</div>
                    <div class="stat-label">Errors Found</div>
                    <div class="stat-desc">{error_rate:.2f}% of requests</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{self.ips_df['total_requests'].max():,}</div>
                    <div class="stat-label">Peak IP Activity</div>
                    <div class="stat-desc">Most requests from single IP</div>
                </div>
            </div>
            """
        
        # Charts (check if files exist)
        charts_exist = {
            'status': os.path.exists('status_distribution.png'),
            'attackers': os.path.exists('top_attackers.png'),
            'temporal': os.path.exists('temporal_analysis.png'),
            'resource': os.path.exists('resource_analysis.png')
        }
        
        if any(charts_exist.values()):
            html += '<div class="chart-container"><h2>📈 Analysis Visualizations</h2>'
            
            if charts_exist['status']:
                html += '<img src="status_distribution.png" style="max-width:100%; margin-bottom:20px;">'
            if charts_exist['attackers']:
                html += '<img src="top_attackers.png" style="max-width:100%; margin-bottom:20px;">'
            if charts_exist['temporal']:
                html += '<img src="temporal_analysis.png" style="max-width:100%; margin-bottom:20px;">'
            if charts_exist['resource']:
                html += '<img src="resource_analysis.png" style="max-width:100%; margin-bottom:20px;">'
            
            html += '</div>'
        
        # Top threats table
        if not self.ips_df.empty and 'error_count' in self.ips_df.columns:
            # Ensure error_rate exists
            if 'error_rate' not in self.ips_df.columns:
                self.ips_df['error_rate'] = self.ips_df['error_count'] / self.ips_df['total_requests']
            
            threats = self.ips_df.nlargest(20, 'error_count')
            
            html += """
            <div class="chart-container">
                <h2>🚨 Top 20 Threat Sources</h2>
                <table>
                    <tr>
                        <th>Rank</th>
                        <th>IP Address</th>
                        <th>Total Requests</th>
                        <th>Error Count</th>
                        <th>Error Rate</th>
                        <th>Threat Level</th>
                    </tr>
            """
            
            for i, (_, row) in enumerate(threats.iterrows()):
                error_rate = row['error_rate'] * 100
                threat_class = 'threat-high' if error_rate > 20 else 'threat-medium' if error_rate > 10 else 'threat-low'
                
                html += f"""
                    <tr>
                        <td>#{i+1}</td>
                        <td><strong>{row['ip']}</strong></td>
                        <td>{row['total_requests']:,}</td>
                        <td>{row['error_count']}</td>
                        <td>{error_rate:.2f}%</td>
                        <td class="{threat_class}">{'HIGH' if error_rate > 20 else 'MEDIUM' if error_rate > 10 else 'LOW'}</td>
                    </tr>
                """
            
            html += "</table></div>"
        
        # Recommendations
        html += """
            <div class="chart-container">
                <h2>🔧 Recommendations</h2>
                <ul>
        """
        
        if not self.ips_df.empty and 'error_count' in self.ips_df.columns:
            # Ensure error_rate exists
            if 'error_rate' not in self.ips_df.columns:
                self.ips_df['error_rate'] = self.ips_df['error_count'] / self.ips_df['total_requests']
            
            high_threat = self.ips_df[self.ips_df['error_rate'] * 100 > 20]
            if len(high_threat) > 0:
                html += f"<li>⚠️ Block {len(high_threat)} IPs with >20% error rate</li>"
            
            scanners = self.ips_df[
                (self.ips_df['error_count'] > 10) & 
                (self.ips_df['error_rate'] > 0.5)
            ]
            if len(scanners) > 0:
                html += f"<li>🔍 Investigate {len(scanners)} potential scanners (50%+ error rate)</li>"
            
            high_volume = self.ips_df[self.ips_df['total_requests'] > 1000]
            if len(high_volume) > 0:
                html += f"<li>📊 Implement rate limiting for {len(high_volume)} IPs with >1000 requests</li>"
        
        # Resource-based recommendations
        if not self.errors_df.empty and 'resource' in self.errors_df.columns:
            top_resources = self.errors_df['resource'].value_counts().head(5)
            if not top_resources.empty:
                html += "<li>🛡️ Add WAF rules for most targeted resources:<ul>"
                for resource, count in top_resources.items():
                    short_resource = resource[:30] + '...' if len(resource) > 30 else resource
                    html += f"<li>{short_resource} ({count} errors)</li>"
                html += "</ul></li>"
        
        html += """
                <li>📈 Set up monitoring for error rate spikes</li>
            </ul></div>
            
            <div class="footer">
                Generated by High-Performance Big Data Log Parser | Analysis completed at """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """
            </div>
        </body>
        </html>
        """
        
        with open('log_analysis_report.html', 'w') as f:
            f.write(html)
        
        print("\n📑 HTML report saved to 'log_analysis_report.html'")
    
    def create_visualizations(self):
        """Create all visualization plots"""
        print("\n🎨 Creating visualizations...")
        
        # Status distribution
        if not self.status_df.empty:
            plt.figure(figsize=(10, 6))
            colors = ['green' if s < 400 else 'orange' if s < 500 else 'red' 
                     for s in self.status_df['status_code']]
            plt.bar(self.status_df['status_code'].astype(str), 
                   self.status_df['count'], color=colors)
            plt.xlabel('HTTP Status Code')
            plt.ylabel('Count')
            plt.title('Status Code Distribution')
            plt.xticks(rotation=45)
            
            # Add value labels
            max_count = self.status_df['count'].max()
            for i, (_, row) in enumerate(self.status_df.iterrows()):
                plt.text(i, row['count'] + max_count*0.01, 
                        f"{row['count']:,}", ha='center', va='bottom', fontweight='bold')
            
            plt.tight_layout()
            plt.savefig('status_distribution.png', dpi=150, bbox_inches='tight')
            print("  ✓ status_distribution.png")
        
        # Top attackers
        if not self.ips_df.empty and 'error_count' in self.ips_df.columns:
            # Ensure error_rate exists
            if 'error_rate' not in self.ips_df.columns:
                self.ips_df['error_rate'] = self.ips_df['error_count'] / self.ips_df['total_requests']
            
            top_attackers = self.ips_df.nlargest(15, 'error_count')
            
            if not top_attackers.empty:
                fig, ax = plt.subplots(figsize=(12, 6))
                bars = ax.barh(range(len(top_attackers)), top_attackers['error_count'], 
                              color='red', alpha=0.7)
                ax.set_yticks(range(len(top_attackers)))
                ax.set_yticklabels([ip[:20] + '...' if len(ip) > 20 else ip 
                                   for ip in top_attackers['ip']])
                ax.set_xlabel('Error Count')
                ax.set_title('Top Attackers by Error Count')
                
                # Add value labels
                max_count = top_attackers['error_count'].max()
                for i, (bar, (_, row)) in enumerate(zip(bars, top_attackers.iterrows())):
                    ax.text(row['error_count'] + max_count*0.01, i, 
                           f"{row['error_count']} ({row['error_rate']:.1%})", 
                           va='center', fontweight='bold')
                
                plt.tight_layout()
                plt.savefig('top_attackers.png', dpi=150, bbox_inches='tight')
                print("  ✓ top_attackers.png")
    
    def run(self):
        """Run complete analysis pipeline"""
        print("\n" + "="*80)
        print("📊 BIG DATA LOG ANALYZER")
        print("="*80)
        
        # Load data
        self.load_parsed_data()
        
        if self.ips_df.empty and self.errors_df.empty and self.status_df.empty:
            print("\n❌ No data to analyze. Please run parser first.")
            return
        
        # Run analyses
        threats = self.analyze_threats()
        self.analyze_temporal_patterns()
        self.analyze_resources()
        
        # Create visualizations
        self.create_visualizations()
        
        # Generate report
        self.generate_report()
        
        # Summary
        print("\n" + "="*80)
        print("✅ ANALYSIS COMPLETE")
        print("="*80)
        print("Generated files:")
        generated = []
        if os.path.exists('status_distribution.png'):
            generated.append('status_distribution.png')
        if os.path.exists('top_attackers.png'):
            generated.append('top_attackers.png')
        if os.path.exists('temporal_analysis.png'):
            generated.append('temporal_analysis.png')
        if os.path.exists('resource_analysis.png'):
            generated.append('resource_analysis.png')
        if os.path.exists('log_analysis_report.html'):
            generated.append('log_analysis_report.html')
        
        for f in generated:
            print(f"  - {f}")
        print("="*80)

def main():
    parser = argparse.ArgumentParser(description='Big Data Log Analyzer')
    parser.add_argument('-e', '--errors', default='parsed_errors.csv',
                       help='Error CSV file (default: parsed_errors.csv)')
    parser.add_argument('-s', '--status', default='parsed_status.csv',
                       help='Status CSV file (default: parsed_status.csv)')
    parser.add_argument('-i', '--ips', default='parsed_ips.csv',
                       help='IP CSV file (default: parsed_ips.csv)')
    parser.add_argument('-d', '--db', default='logs.db',
                       help='SQLite database path (default: logs.db)')
    
    args = parser.parse_args()
    
    analyzer = LogAnalyzer(args.db)
    analyzer.run()

if __name__ == "__main__":
    main()
