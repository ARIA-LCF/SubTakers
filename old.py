import subprocess
import sys
import os
import json
import concurrent.futures
from tqdm import tqdm
import argparse
import logging
from typing import List, Dict, Any, Set, Tuple
import time
import requests
import urllib3
from datetime import datetime

# غیرفعال کردن هشدارهای SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# تنظیمات لاگینگ
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('subdomain_tool.log'),
        logging.StreamHandler()
    ]
)

# نمایش بنر
def show_banner():
    banner = r"""
   ____        _     _        _             
  / ___| _   _| |__ | |_ __ _| | _____ _ __ 
  \___ \| | | | '_ \| __/ _` | |/ / _ \ '__|
   ___) | |_| | |_) | || (_| |   <  __/ |   
  |____/ \__,_|_.__/ \__\__,_|_|\_\___|_|   
  Telegram Channel: @LCFkie | Version: 0.1                                         
                                         
    """
    print(banner)
    print("=" * 60)
    print("Subdomain Enumeration & CNAME Analysis Tool")
    print("=" * 60)

# نمایش منوی اصلی
def show_main_menu():
    print("\n" + "=" * 60)
    print("MAIN MENU")
    print("=" * 60)
    print("1. Find Subdomains for Multiple Domains (from file)")
    print("2. Find Subdomains for a Single Domain")
    print("3. Check CNAME Records for Subdomains")
    print("4. Check for Subdomain Takeover")
    print("5. Help")
    print("0. Exit")
    print("=" * 60)
    
    choice = input("Please select an option (0-5): ").strip()
    return choice

# نمایش منوی Help
def show_help():
    print("\n" + "=" * 60)
    print("HELP")
    print("=" * 60)
    print("1. Find Subdomains for Multiple Domains:")
    print("   - Reads domains from a file (default: domains.txt)")
    print("   - Finds subdomains using multiple sources")
    print("   - Saves results to subdomains.txt")
    print()
    print("2. Find Subdomains for a Single Domain:")
    print("   - Enter a single domain to analyze")
    print("   - Finds subdomains using multiple sources")
    print("   - Saves results to a custom file")
    print()
    print("3. Check CNAME Records for Subdomains:")
    print("   - Reads subdomains from a file (default: subdomains.txt)")
    print("   - Checks CNAME records for each subdomain")
    print("   - Saves results to cnames.txt")
    print()
    print("4. Check for Subdomain Takeover:")
    print("   - Reads CNAME records from a file (default: cnames.txt)")
    print("   - Checks for potential subdomain takeover vulnerabilities")
    print("   - Saves results to takeovers.txt")
    print()
    print("5. Help: Shows this information")
    print("0. Exit: Exits the program")
    print("=" * 60)
    input("Press Enter to return to main menu...")

# کلاس برای پیدا کردن ساب‌دامین
class SubdomainFinder:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
    
    def get_from_crtsh(self, domain: str) -> Set[str]:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        subs = set()
        try:
            response = self.session.get(url, timeout=15)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    for sub in entry['name_value'].split("\n"):
                        sub = sub.strip().lower()
                        if sub and (sub == domain or sub.endswith('.' + domain)):
                            subs.add(sub)
        except Exception as e:
            logging.error(f"[crt.sh] error for {domain}: {e}")
        return subs

    def get_from_alienvault(self, domain: str) -> Set[str]:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        subs = set()
        try:
            response = self.session.get(url, timeout=15)
            if response.status_code == 200:
                data = response.json()
                for entry in data.get("passive_dns", []):
                    hostname = entry.get("hostname", "").lower()
                    if hostname and (hostname == domain or hostname.endswith('.' + domain)):
                        subs.add(hostname)
        except Exception as e:
            logging.error(f"[AlienVault] error for {domain}: {e}")
        return subs

    def get_from_threatcrowd(self, domain: str) -> Set[str]:
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
        subs = set()
        try:
            response = self.session.get(url, timeout=15, verify=False)
            if response.status_code == 200:
                data = response.json()
                for sub in data.get("subdomains", []):
                    sub = sub.strip().lower()
                    if sub and (sub == domain or sub.endswith('.' + domain)):
                        subs.add(sub)
        except Exception as e:
            logging.error(f"[ThreatCrowd] error for {domain}: {e}")
        return subs

    def get_from_hackertarget(self, domain: str) -> Set[str]:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        subs = set()
        try:
            response = self.session.get(url, timeout=15)
            if response.status_code == 200:
                for line in response.text.splitlines():
                    if line.strip():
                        sub = line.split(",")[0].strip().lower()
                        if sub and (sub == domain or sub.endswith('.' + domain)):
                            subs.add(sub)
        except Exception as e:
            logging.error(f"[HackerTarget] error for {domain}: {e}")
        return subs

    def find_subdomains(self, domain: str) -> Set[str]:
        all_subs = set()
        all_subs |= self.get_from_crtsh(domain)
        time.sleep(1)
        all_subs |= self.get_from_alienvault(domain)
        time.sleep(1)
        all_subs |= self.get_from_threatcrowd(domain)
        time.sleep(1)
        all_subs |= self.get_from_hackertarget(domain)
        return all_subs

# کلاس برای بررسی CNAME (بدون نیاز به dnspython)
class CNAMEChecker:
    def __init__(self, max_workers: int = 10, timeout: int = 30):
        self.max_workers = max_workers
        self.timeout = timeout
    
    def normalize_domain(self, domain: str) -> str:
        domain = domain.strip()
        if domain.startswith(('http://', 'https://')):
            domain = domain.split('//')[1]
        domain = domain.split('/')[0]
        domain = domain.split('?')[0]
        return domain.lower()
    
    def get_cname_with_dig(self, domain: str) -> List[str]:
        try:
            result = subprocess.run(
                ["dig", "+short", "CNAME", domain],
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=True
            )
            cnames = [cname.strip().rstrip('.') for cname in result.stdout.splitlines() if cname.strip()]
            return cnames
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
            logging.warning(f"dig command failed for {domain}: {e}")
            return []
    
    def get_cname(self, domain: str) -> List[str]:
        domain = self.normalize_domain(domain)
        return self.get_cname_with_dig(domain)
    
    def check_domain(self, domain: str) -> Dict[str, Any]:
        normalized_domain = self.normalize_domain(domain)
        cnames = self.get_cname(normalized_domain)
        
        return {
            'original_domain': domain,
            'normalized_domain': normalized_domain,
            'cnames': cnames,
            'has_cname': len(cnames) > 0,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }
    
    def check_domains(self, domains: List[str]) -> List[Dict[str, Any]]:
        results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_domain = {
                executor.submit(self.check_domain, domain): domain 
                for domain in domains
            }
            
            for future in tqdm(concurrent.futures.as_completed(future_to_domain), 
                              total=len(domains), desc="Checking CNAMEs", unit="domain"):
                domain = future_to_domain[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    logging.error(f"Error processing {domain}: {e}")
                    results.append({
                        'original_domain': domain,
                        'normalized_domain': self.normalize_domain(domain),
                        'cnames': [],
                        'has_cname': False,
                        'error': str(e),
                        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                    })
        
        return results

# کلاس برای بررسی Subdomain Takeover
class TakeoverChecker:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.vulnerable_services = {
            'github.io': 'GitHub Pages',
            'herokuapp.com': 'Heroku',
            'azurewebsites.net': 'Azure Web Apps',
            'cloudapp.net': 'Azure Cloud Services',
            'cloudapp.azure.com': 'Azure Cloud Services',
            'trafficmanager.net': 'Azure Traffic Manager',
            'blob.core.windows.net': 'Azure Blob Storage',
            'azure-api.net': 'Azure API Management',
            's3.amazonaws.com': 'AWS S3',
            'amazonaws.com': 'AWS',
            'elasticbeanstalk.com': 'AWS Elastic Beanstalk',
            'onrender.com': 'Render',
            'firebaseapp.com': 'Firebase',
            'web.app': 'Firebase',
            'ghost.io': 'Ghost',
            'surge.sh': 'Surge',
            'readme.io': 'Readme',
            'helpjuice.com': 'Helpjuice',
            'helpscoutdocs.com': 'Helpscout',
            'wordpress.com': 'WordPress',
            'pantheonsite.io': 'Pantheon',
            'myshopify.com': 'Shopify',
            'statuspage.io': 'Statuspage',
            'uservoice.com': 'UserVoice',
            'wpengine.com': 'WPEngine',
            'cloudfront.net': 'AWS CloudFront',
            'netlify.app': 'Netlify',
            'azurestaticapps.net': 'Azure Static Apps'
        }
    
    def check_takeover(self, subdomain: str, cname: str) -> Dict[str, Any]:
        result = {
            'subdomain': subdomain,
            'cname': cname,
            'vulnerable_service': None,
            'status_code': None,
            'error': None,
            'is_vulnerable': False,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # بررسی آیا CNAME به یک سرویس آسیب‌پذیر اشاره می‌کند
        for service_domain, service_name in self.vulnerable_services.items():
            if service_domain in cname:
                result['vulnerable_service'] = service_name
                break
        
        if not result['vulnerable_service']:
            return result
        
        # بررسی HTTP response
        try:
            response = self.session.get(
                f"http://{subdomain}", 
                timeout=10, 
                allow_redirects=True,
                verify=False
            )
            result['status_code'] = response.status_code
            
            # بررسی نشانه‌های احتمالی takeover
            content = response.text.lower()
            error_keywords = [
                'not found', '404', 'no such app', 'page not found',
                'does not exist', 'is not registered', 'no site configured',
                'project not found', 'application error', 'bad gateway',
                'the specified bucket does not exist'
            ]
            
            if any(keyword in content for keyword in error_keywords):
                result['is_vulnerable'] = True
                
        except requests.exceptions.RequestException as e:
            result['error'] = str(e)
            # اگر خطای اتصال وجود دارد، ممکن است آسیب‌پذیر باشد
            if "connection" in str(e).lower() or "timeout" in str(e).lower():
                result['is_vulnerable'] = True
        
        return result
    
    def check_takeovers(self, cname_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        results = []
        takeover_candidates = []
        
        # جمع‌آوری تمام ساب‌دامین‌هایی که CNAME دارند
        for item in cname_data:
            if item['has_cname']:
                for cname in item['cnames']:
                    takeover_candidates.append((item['normalized_domain'], cname))
        
        if not takeover_candidates:
            return results
        
        # بررسی takeover برای هر کاندید
        for subdomain, cname in tqdm(takeover_candidates, desc="Checking for takeovers", unit="domain"):
            result = self.check_takeover(subdomain, cname)
            results.append(result)
        
        return results

# تابع برای پیدا کردن ساب‌دامین‌های چند دامنه
def find_subdomains_multiple():
    print("\n" + "=" * 60)
    print("FIND SUBDOMAINS FOR MULTIPLE DOMAINS")
    print("=" * 60)
    
    input_file = input("Enter the path to domains file (default: domains.txt): ").strip()
    if not input_file:
        input_file = "domains.txt"
    
    if not os.path.isfile(input_file):
        print(f"File not found: {input_file}")
        input("Press Enter to return to main menu...")
        return
    
    output_file = input("Enter output file name (default: subdomains.txt): ").strip()
    if not output_file:
        output_file = "subdomains.txt"
    
    # خواندن دامنه‌ها
    with open(input_file, 'r') as f:
        domains = [line.strip() for line in f if line.strip()]
    
    if not domains:
        print("No domains found in the file!")
        input("Press Enter to return to main menu...")
        return
    
    print(f"Found {len(domains)} domains to process")
    
    # پیدا کردن ساب‌دامین‌ها
    finder = SubdomainFinder()
    all_subdomains = set()
    
    for domain in tqdm(domains, desc="Finding subdomains", unit="domain"):
        try:
            subs = finder.find_subdomains(domain)
            all_subdomains.update(subs)
            print(f"Found {len(subs)} subdomains for {domain}")
        except Exception as e:
            print(f"Error processing {domain}: {e}")
    
    # ذخیره نتایج
    with open(output_file, 'w') as f:
        for sub in sorted(all_subdomains):
            f.write(sub + "\n")
    
    print(f"\nDone! Found {len(all_subdomains)} unique subdomains")
    print(f"Results saved to {output_file}")
    input("Press Enter to return to main menu...")

# تابع برای پیدا کردن ساب‌دامین‌های یک دامنه
def find_subdomains_single():
    print("\n" + "=" * 60)
    print("FIND SUBDOMAINS FOR A SINGLE DOMAIN")
    print("=" * 60)
    
    domain = input("Enter the domain to analyze: ").strip()
    if not domain:
        print("Domain cannot be empty!")
        input("Press Enter to return to main menu...")
        return
    
    output_file = input("Enter output file name (default: subdomains.txt): ").strip()
    if not output_file:
        output_file = "subdomains.txt"
    
    # پیدا کردن ساب‌دامین‌ها
    finder = SubdomainFinder()
    print(f"Finding subdomains for {domain}...")
    
    try:
        subdomains = finder.find_subdomains(domain)
        print(f"Found {len(subdomains)} subdomains for {domain}")
        
        # ذخیره نتایج
        with open(output_file, 'w') as f:
            for sub in sorted(subdomains):
                f.write(sub + "\n")
        
        print(f"Results saved to {output_file}")
    except Exception as e:
        print(f"Error processing {domain}: {e}")
    
    input("Press Enter to return to main menu...")

# تابع برای بررسی CNAMEها
def check_cnames():
    print("\n" + "=" * 60)
    print("CHECK CNAME RECORDS")
    print("=" * 60)
    
    input_file = input("Enter the path to subdomains file (default: subdomains.txt): ").strip()
    if not input_file:
        input_file = "subdomains.txt"
    
    if not os.path.isfile(input_file):
        print(f"File not found: {input_file}")
        input("Press Enter to return to main menu...")
        return
    
    output_file = input("Enter output file name (default: cnames.txt): ").strip()
    if not output_file:
        output_file = "cnames.txt"
    
    # خواندن ساب‌دامین‌ها
    with open(input_file, 'r') as f:
        subdomains = [line.strip() for line in f if line.strip()]
    
    if not subdomains:
        print("No subdomains found in the file!")
        input("Press Enter to return to main menu...")
        return
    
    print(f"Found {len(subdomains)} subdomains to process")
    
    # بررسی CNAMEها
    checker = CNAMEChecker()
    results = checker.check_domains(subdomains)
    
    # ذخیره نتایج - فقط مواردی که CNAME دارند
    domains_with_cname = 0
    with open(output_file, 'w') as f:
        for result in results:
            if result['has_cname']:
                domains_with_cname += 1
                for cname in result['cnames']:
                    f.write(f"{result['normalized_domain']} -> {cname}\n")
    
    # نمایش آمار
    print(f"\nDone! Processed {len(subdomains)} subdomains")
    print(f"Found {domains_with_cname} subdomains with CNAME records")
    
    if domains_with_cname == 0:
        print("No CNAME records found. The output file is empty.")
    else:
        print(f"Results saved to {output_file}")
    
    input("Press Enter to return to main menu...")

# تابع برای بررسی Subdomain Takeover
def check_takeovers():
    print("\n" + "=" * 60)
    print("CHECK FOR SUBDOMAIN TAKEOVER")
    print("=" * 60)
    
    input_file = input("Enter the path to CNAMEs file (default: cnames.txt): ").strip()
    if not input_file:
        input_file = "cnames.txt"
    
    if not os.path.isfile(input_file):
        print(f"File not found: {input_file}")
        input("Press Enter to return to main menu...")
        return
    
    output_file = input("Enter output file name (default: takeovers.txt): ").strip()
    if not output_file:
        output_file = "takeovers.txt"
    
    # خواندن CNAMEها
    cname_data = []
    with open(input_file, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or "->" not in line:
                continue
            
            parts = line.split("->")
            if len(parts) == 2:
                subdomain = parts[0].strip()
                cname = parts[1].strip()
                
                if cname.lower() != "no cname found":
                    cname_data.append({
                        'normalized_domain': subdomain,
                        'cnames': [cname],
                        'has_cname': True
                    })
    
    if not cname_data:
        print("No CNAME records found in the file!")
        input("Press Enter to return to main menu...")
        return
    
    print(f"Found {len(cname_data)} CNAME records to process")
    
    # بررسی takeover
    checker = TakeoverChecker()
    results = checker.check_takeovers(cname_data)
    
    # ذخیره نتایج
    vulnerable_count = 0
    with open(output_file, 'w') as f:
        f.write("SUBDOMAIN TAKEOVER ANALYSIS RESULTS\n")
        f.write("=" * 50 + "\n")
        f.write(f"Generated at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 50 + "\n\n")
        
        for result in results:
            if result['is_vulnerable']:
                vulnerable_count += 1
                f.write(f"[!] POTENTIAL TAKEOVER: {result['subdomain']}\n")
                f.write(f"    CNAME: {result['cname']}\n")
                f.write(f"    Service: {result['vulnerable_service']}\n")
                if result['status_code']:
                    f.write(f"    Status Code: {result['status_code']}\n")
                if result['error']:
                    f.write(f"    Error: {result['error']}\n")
                f.write("\n")
        
        if vulnerable_count == 0:
            f.write("No potential subdomain takeovers found.\n")
    
    print(f"\nDone! Processed {len(results)} CNAME records")
    if vulnerable_count > 0:
        print(f"Found {vulnerable_count} potentially vulnerable subdomains")
    else:
        print("No potential subdomain takeovers found")
    print(f"Results saved to {output_file}")
    input("Press Enter to return to main menu...")

# تابع اصلی
def main():
    show_banner()
    
    while True:
        choice = show_main_menu()
        
        if choice == '0':
            print("Goodbye!")
            break
        elif choice == '1':
            find_subdomains_multiple()
        elif choice == '2':
            find_subdomains_single()
        elif choice == '3':
            check_cnames()
        elif choice == '4':
            check_takeovers()
        elif choice == '5':
            show_help()
        else:
            print("Invalid choice! Please try again.")
            input("Press Enter to continue...")

if __name__ == "__main__":
    main()
