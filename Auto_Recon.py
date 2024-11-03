#!/usr/bin/env python3

import requests
from bs4 import BeautifulSoup
import socket
import re
import ssl
import dns.resolver
import whois
from datetime import datetime
import json
from colorama import init, Fore, Style
from tabulate import tabulate
from urllib.parse import urlparse
from collections import defaultdict
from typing import List, Dict, Any, Optional
import time
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

# Initialize colorama for cross-platform color support
init(autoreset=True)

def print_banner():
    """Display the tool's banner with combined branding"""
    banner = f"""
    {Fore.CYAN}█▄▄ ▄▀█ █▀█     █▀█     █▀▀ █ █▄░█
    {Fore.BLUE}█▄█ █▀█ █▀▄ █▄▄     █▄▀     █ █░▀█
    
    {Fore.YELLOW}[*] Enhanced Security Analysis & Reconnaissance Tool
    {Fore.WHITE}[*] Version 3.0 - Combined Features Edition
    {Style.RESET_ALL}
    """
    print(banner)

class SecurityAnalyzer:
    def __init__(self, url: str, api_key: Optional[str] = None):
        """
        Initialize the security analyzer with enhanced capabilities.
        
        Args:
            url (str): Target URL to analyze
            api_key (str, optional): API key for additional services
        """
        self.url = self.normalize_url(url)
        self.domain = urlparse(self.url).netloc
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0'
        })
        
        # Disable SSL warnings for analysis purposes
        requests.packages.urllib3.disable_warnings()

    @staticmethod
    def normalize_url(url: str) -> str:
        """Normalize URL format with enhanced validation"""
        if not url:
            raise ValueError("URL cannot be empty")
            
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        return url

    def print_section_header(self, title: str) -> None:
        """Print formatted section header with consistent styling"""
        print(f"\n{Fore.CYAN}{'═' * 20} {title} {'═' * 20}{Style.RESET_ALL}")

    def get_dns_records(self) -> Dict[str, List[str]]:
        """Enhanced DNS record retrieval with comprehensive error handling"""
        self.print_section_header("DNS Records Analysis")
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.domain, record_type)
                records[record_type] = [str(answer) for answer in answers]
                
                print(f"\n{Fore.GREEN}[+] {record_type} Records:{Style.RESET_ALL}")
                if record_type == 'MX':
                    # Special handling for MX records to show priority
                    mx_data = [[ans.preference, str(ans.exchange)] for ans in answers]
                    print(tabulate(mx_data, headers=['Priority', 'Mail Server'], tablefmt='simple'))
                else:
                    for record in records[record_type]:
                        print(f"  {Fore.WHITE}➜ {record}{Style.RESET_ALL}")
                    
            except dns.resolver.NoAnswer:
                print(f"{Fore.YELLOW}[!] No {record_type} records found{Style.RESET_ALL}")
            except dns.resolver.NXDOMAIN:
                print(f"{Fore.RED}[!] Domain does not exist{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[!] Error retrieving {record_type} records: {str(e)}{Style.RESET_ALL}")
        
        return records

    def get_whois_info(self) -> Dict[str, Any]:
        """Get WHOIS information with improved parsing and presentation"""
        self.print_section_header("WHOIS Information")
        try:
            domain_info = whois.whois(self.domain)
            
            # Format WHOIS data for display
            whois_data = {
                "Domain Name": domain_info.domain_name,
                "Registrar": domain_info.registrar,
                "Creation Date": domain_info.creation_date,
                "Expiration Date": domain_info.expiration_date,
                "Updated Date": domain_info.updated_date,
                "Name Servers": domain_info.name_servers,
                "Status": domain_info.status,
                "Emails": domain_info.emails,
                "Organization": domain_info.org,
            }
            
            # Print formatted WHOIS information
            for key, value in whois_data.items():
                if value:
                    if isinstance(value, (list, tuple)):
                        print(f"{Fore.GREEN}[+] {key}:{Style.RESET_ALL}")
                        for item in value:
                            print(f"  {Fore.WHITE}➜ {item}{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.GREEN}[+] {key}: {Fore.WHITE}{value}{Style.RESET_ALL}")
            
            return whois_data
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error retrieving WHOIS information: {str(e)}{Style.RESET_ALL}")
            return {}

    def analyze_security_headers(self) -> Dict[str, str]:
        """Analyze security headers with enhanced checks and recommendations"""
        self.print_section_header("Security Headers Analysis")
        try:
            response = self.session.get(self.url, verify=False, timeout=10)
            headers = response.headers
            
            security_headers = {
                'Strict-Transport-Security': {
                    'name': 'HSTS',
                    'description': 'Enforces HTTPS connections'
                },
                'Content-Security-Policy': {
                    'name': 'CSP',
                    'description': 'Controls resource loading'
                },
                'X-Frame-Options': {
                    'name': 'Frame Options',
                    'description': 'Prevents clickjacking'
                },
                'X-Content-Type-Options': {
                    'name': 'Content Type Options',
                    'description': 'Prevents MIME sniffing'
                },
                'X-XSS-Protection': {
                    'name': 'XSS Protection',
                    'description': 'Helps prevent XSS attacks'
                },
                'Referrer-Policy': {
                    'name': 'Referrer Policy',
                    'description': 'Controls referrer information'
                },
                'Permissions-Policy': {
                    'name': 'Permissions Policy',
                    'description': 'Controls browser features'
                }
            }
            
            results = {}
            for header, info in security_headers.items():
                if header in headers:
                    print(f"{Fore.GREEN}[+] {info['name']} implemented:{Style.RESET_ALL}")
                    print(f"  {Fore.WHITE}➜ {headers[header]}{Style.RESET_ALL}")
                    results[header] = headers[header]
                else:
                    print(f"{Fore.RED}[-] {info['name']} missing - {info['description']}{Style.RESET_ALL}")
                    results[header] = None
            
            return results
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error analyzing security headers: {str(e)}{Style.RESET_ALL}")
            return {}

    def check_ssl_cert(self) -> Dict[str, Any]:
        """Comprehensive SSL certificate analysis"""
        self.print_section_header("SSL Certificate Analysis")
        try:
            hostname = self.domain
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Extract and format certificate information
                    cert_info = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serialNumber': cert['serialNumber'],
                        'notBefore': cert['notBefore'],
                        'notAfter': cert['notAfter']
                    }
                    
                    # Calculate certificate validity
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_remaining = (not_after - datetime.now()).days
                    
                    print(f"{Fore.GREEN}[+] Certificate Information:{Style.RESET_ALL}")
                    print(f"  {Fore.WHITE}➜ Subject: {cert_info['subject']}{Style.RESET_ALL}")
                    print(f"  {Fore.WHITE}➜ Issuer: {cert_info['issuer']}{Style.RESET_ALL}")
                    print(f"  {Fore.WHITE}➜ Valid Until: {cert_info['notAfter']}{Style.RESET_ALL}")
                    print(f"  {Fore.WHITE}➜ Days Remaining: {days_remaining}{Style.RESET_ALL}")
                    
                    # Add validity warning if certificate is expiring soon
                    if days_remaining < 30:
                        print(f"{Fore.RED}[!] Warning: Certificate expires in {days_remaining} days{Style.RESET_ALL}")
                    
                    return cert_info
                    
        except ssl.SSLError as e:
            print(f"{Fore.RED}[!] SSL Error: {str(e)}{Style.RESET_ALL}")
        except socket.gaierror as e:
            print(f"{Fore.RED}[!] DNS Resolution Error: {str(e)}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error checking SSL certificate: {str(e)}{Style.RESET_ALL}")
        
        return {}

    def scrape_subdomains(self) -> List[str]:
        """Discover subdomains through various methods"""
        self.print_section_header("Subdomain Discovery")
        try:
            response = requests.get(self.url)
            html = response.text
            
            # Find subdomains in HTML content
            pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}'
            subdomains = set(re.findall(pattern, html))
            
            # Filter relevant subdomains
            relevant_subdomains = [
                sub for sub in subdomains 
                if self.domain in sub and sub != self.domain
            ]
            
            if relevant_subdomains:
                print(f"{Fore.GREEN}[+] Discovered Subdomains:{Style.RESET_ALL}")
                for subdomain in sorted(relevant_subdomains):
                    print(f"  {Fore.WHITE}➜ {subdomain}{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[!] No subdomains discovered{Style.RESET_ALL}")
            
            return list(relevant_subdomains)
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error during subdomain discovery: {str(e)}{Style.RESET_ALL}")
            return []

    def check_breach_history(self) -> List[Dict[str, Any]]:
        """Check for security breaches using HaveIBeenPwned API"""
        if not self.api_key:
            print(f"{Fore.YELLOW}[!] API key required for breach history check{Style.RESET_ALL}")
            return []
            
        self.print_section_header("Breach History Analysis")
        try:
            url = f"https://haveibeenpwned.com/api/v3/breaches?domain={self.domain}"
            headers = {
                'hibp-api-key': self.api_key,
                'User-Agent': 'SecurityAnalyzer/3.0'
            }
            
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            breaches = response.json()
            
            if not breaches:
                print(f"{Fore.GREEN}[+] No known breaches found{Style.RESET_ALL}")
                return []
            
            print(f"{Fore.YELLOW}[!] Found {len(breaches)} breach(es){Style.RESET_ALL}")
            
            for breach in breaches:
                print(f"\n{Fore.RED}[!] Breach Details:{Style.RESET_ALL}")
                print(f"  {Fore.WHITE}➜ Title: {breach['Title']}{Style.RESET_ALL}")
                print(f"  {Fore.WHITE}➜ Date: {breach['BreachDate']}{Style.RESET_ALL}")
                print(f"  {Fore.WHITE}➜ Pwned Accounts: {breach['PwnCount']:,}{Style.RESET_ALL}")
                
                if 'DataClasses' in breach:
                    print(f"  {Fore.WHITE}➜ Compromised Data:{Style.RESET_ALL}")
                    for data_type in breach['DataClasses']:
                        print(f"    - {data_type}")
            
            return breaches
            
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[!] Error checking breach history: {str(e)}{Style.RESET_ALL}")
            return []

def main():
    try:
        # Clear screen and show banner
        os.system('clear' if os.name == 'posix' else 'cls')
        print_banner()
        
        # Get user input
        url = input(f"{Fore.CYAN}[?] Enter target URL: {Style.RESET_ALL}")
        api_key = input(f"{Fore.CYAN}[?] Enter HaveIBeenPwned API key (optional): {Style.RESET_ALL}")
        
        # Initialize analyzer
        analyzer = SecurityAnalyzer(url, api_key)
        
        print(f"\n{Fore.YELLOW}[*] Starting comprehensive analysis of {analyzer.url}{Style.RESET_ALL}")
        start_time = time.time()
        
        # Run each analysis in sequence, instead of using ThreadPoolExecutor for debugging
        dns_records = analyzer.get_dns_records()
        whois_info = analyzer.get_whois_info()
        security_headers = analyzer.analyze_security_headers()
        ssl_cert = analyzer.check_ssl_cert()
        subdomains = analyzer.scrape_subdomains()
        breach_history = analyzer.check_breach_history()

        # Print the total time taken
        elapsed_time = time.time() - start_time
        print(f"\n{Fore.CYAN}[*] Analysis completed in {elapsed_time:.2f} seconds.{Style.RESET_ALL}")
    
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Program interrupted by user.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()

