import os
import subprocess
import sys
import time
import requests
import dns.resolver
import concurrent.futures
import urllib3
import json
from datetime import datetime

# غیرفعال کردن هشدارهای SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ایجاد پوشه خروجی بر اساس تاریخ و زمان
def create_output_directory():
    """ایجاد پوشه خروجی بر اساس تاریخ و زمان فعلی"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = os.path.join("results", f"scan_{timestamp}")
    os.makedirs(output_dir, exist_ok=True)
    return output_dir

# نمایش بنر
def show_banner():
    banner = r"""
     ____        _     _        _             
    / ___| _   _| |__ | |_ __ _| | _____ _ __ 
    \___ \| | | | '_ \| __/ _` | |/ / _ \ '__|
     ___) | |_| | |_) | || (_| |   <  __/ |   
    |____/ \__,_|_.__/ \__\__,_|_|\_\___|_|   
    Telegram Channel: @LCFkie | Version: 1.0                                    
                                         
    """
    print(banner)
    print("=" * 60)
    print("Subdomain Enumeration & Takeover Detection Tool")
    print("=" * 60)

# نمایش منوی اصلی
def show_main_menu():
    print("\n" + "=" * 60)
    print("MAIN MENU")
    print("=" * 60)
    print("1. Find Subdomains")
    print("2. Check CNAME Records")
    print("3. Detect Subdomain Takeover")
    print("4. Back to Previous Menu")
    print("5. Help & Information")
    print("0. Exit")
    print("=" * 60)
    
    choice = input("Please select an option (0-5): ").strip()
    return choice

# نمایش منوی Help
def show_help():
    print("\n" + "=" * 60)
    print("HELP & INFORMATION")
    print("=" * 60)
    print("1. Find Subdomains:")
    print("   - Uses multiple tools (subfinder, assetfinder, amass, etc.)")
    print("   - Input: domains.txt file or single domain")
    print("   - Output: subdomains.txt")
    print()
    print("2. Check CNAME Records:")
    print("   - Checks CNAME records for subdomains")
    print("   - Input: subdomains.txt (default)")
    print("   - Output: cnames.txt (only if CNAMEs found)")
    print()
    print("3. Detect Subdomain Takeover:")
    print("   - Checks for potential subdomain takeover vulnerabilities")
    print("   - Input: cnames.txt (default)")
    print("   - Output: takeover_results.json")
    print()
    print("What is Subdomain Takeover?")
    print("Subdomain takeover occurs when a subdomain points to a service")
    print("(e.g., GitHub Pages, Heroku, AWS S3) that has been removed or")
    print("deleted, allowing an attacker to claim the subdomain.")
    print()
    print("Common vulnerable services:")
    print("- GitHub Pages (*.github.io)")
    print("- Heroku (*.herokuapp.com)")
    print("- AWS S3 (*.s3.amazonaws.com)")
    print("- Firebase (*.firebaseapp.com, *.web.app)")
    print("- Netlify (*.netlify.app)")
    print("- Azure (*.azurewebsites.net)")
    print("=" * 60)
    input("Press Enter to return to main menu...")

def run_command(command, description):
    """اجرای یک دستور و نمایش خروجی"""
    print(f"\n[{description}]")
    print(f"Running: {command}")
    
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=300)
        if result.returncode == 0:
            print("✓ Success")
            return result.stdout
        else:
            print(f"✗ Error: {result.stderr}")
            return None
    except subprocess.TimeoutExpired:
        print("✗ Timeout")
        return None
    except Exception as e:
        print(f"✗ Exception: {e}")
        return None

def install_tools():
    """نصب ابزارهای مورد نیاز"""
    print("Installing required tools...")
    
    tools = [
        "apt update",
        "apt install -y subfinder assetfinder amass sublist3r findomain knockpy dnsutils",
        "git clone https://github.com/projectdiscovery/subfinder.git",
        "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "go install -v github.com/tomnomnom/assetfinder@latest",
        "go install -v github.com/OWASP/Amass/v3/...@master",
        "pip install sublist3r",
        "wget https://github.com/findomain/findomain/releases/latest/download/findomain-linux -O /usr/bin/findomain && chmod +x /usr/bin/findomain"
    ]
    
    for tool in tools:
        run_command(tool, f"Installing {tool.split()[0]}")

def subdomain_enumeration():
    """انجام Subdomain Enumeration با ابزارهای مختلف"""
    print("\n" + "=" * 60)
    print("SUBDOMAIN ENUMERATION")
    print("=" * 60)
    
    # ایجاد پوشه خروجی
    output_dir = create_output_directory()
    print(f"Output directory: {output_dir}")
    
    # دریافت ورودی
    input_type = input("Enter input type (1-file, 2-single domain): ").strip()
    
    domains = []
    if input_type == "1":
        input_file = input("Enter domains file path (default: domains.txt): ").strip()
        if not input_file:
            input_file = "domains.txt"
        
        if not os.path.isfile(input_file):
            print(f"File not found: {input_file}")
            return None, None
        
        with open(input_file, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
    else:
        domain = input("Enter the target domain (e.g., example.com): ").strip()
        if domain:
            domains = [domain]
    
    if not domains:
        print("No domains provided!")
        return None, None
    
    # کپی کردن فایل domains.txt به پوشه خروجی
    domains_output = os.path.join(output_dir, "domains.txt")
    with open(domains_output, 'w') as f:
        for domain in domains:
            f.write(f"{domain}\n")
    print(f"✓ Domains list saved to: {domains_output}")
    
    all_subdomains = set()
    
    for domain in domains:
        print(f"\nProcessing domain: {domain}")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(output_dir, f"subdomains_{domain}_{timestamp}.txt")
        
        # اجرای ابزارهای مختلف
        tools_output = []
        
        # 1. subfinder
        subfinder_cmd = f"subfinder -d {domain} -silent"
        output = run_command(subfinder_cmd, "Subfinder")
        if output:
            tools_output.append(output)
        
        # 2. assetfinder
        assetfinder_cmd = f"assetfinder --subs-only {domain}"
        output = run_command(assetfinder_cmd, "Assetfinder")
        if output:
            tools_output.append(output)
        
        # 3. amass
        amass_cmd = f"amass enum -passive -d {domain}"
        output = run_command(amass_cmd, "Amass")
        if output:
            tools_output.append(output)
        
        # 4. sublist3r
        sublist3r_cmd = f"python -m sublist3r -d {domain}"
        output = run_command(sublist3r_cmd, "Sublist3r")
        if output:
            tools_output.append(output)
        
        # 5. findomain
        findomain_cmd = f"findomain -t {domain} --quiet"
        output = run_command(findomain_cmd, "Findomain")
        if output:
            tools_output.append(output)
        
        # ترکیب و یکتا کردن نتایج
        for output in tools_output:
            if output:
                subdomains = output.strip().split('\n')
                all_subdomains.update([s.strip() for s in subdomains if s.strip()])
        
        # ذخیره نتایج برای این دامنه
        with open(output_file, 'w') as f:
            for subdomain in sorted([s for s in all_subdomains if s.endswith(domain)]):
                f.write(f"{subdomain}\n")
        
        print(f"✓ Found {len([s for s in all_subdomains if s.endswith(domain)])} subdomains for {domain}")
        print(f"✓ Results saved to: {output_file}")
    
    # ذخیره نتایج نهایی
    final_output = os.path.join(output_dir, "subdomains_final.txt")
    with open(final_output, 'w') as f:
        for subdomain in sorted(all_subdomains):
            f.write(f"{subdomain}\n")
    
    print(f"\n✓ Found {len(all_subdomains)} unique subdomains total")
    print(f"✓ Final results saved to: {final_output}")
    
    return list(all_subdomains), output_dir

def check_cnames():
    """بررسی CNAME records برای ساب‌دامین‌ها"""
    print("\n" + "=" * 60)
    print("CHECK CNAME RECORDS")
    print("=" * 60)
    
    # ایجاد پوشه خروجی
    output_dir = create_output_directory()
    print(f"Output directory: {output_dir}")
    
    # دریافت فایل ورودی
    input_file = input("Enter subdomains file path (default: use latest results): ").strip()
    if not input_file:
        # یافتن آخرین فایل subdomains_final.txt
        results_dir = "results"
        if not os.path.exists(results_dir):
            print("No results directory found! Please run subdomain enumeration first.")
            return None, None
        
        # پیدا کردن آخرین پوشه اسکن
        scan_folders = [f for f in os.listdir(results_dir) if f.startswith("scan_") and os.path.isdir(os.path.join(results_dir, f))]
        if not scan_folders:
            print("No scan folders found! Please run subdomain enumeration first.")
            return None, None
        
        latest_scan = max(scan_folders)
        input_file = os.path.join(results_dir, latest_scan, "subdomains_final.txt")
    
    if not os.path.isfile(input_file):
        print(f"File not found: {input_file}")
        return None, None
    
    # خواندن ساب‌دامین‌ها
    with open(input_file, 'r') as f:
        subdomains = [line.strip() for line in f if line.strip()]
    
    if not subdomains:
        print("No subdomains found in the file!")
        return None, None
    
    print(f"Found {len(subdomains)} subdomains to process")
    
    cname_results = []
    
    for subdomain in subdomains:
        dig_cmd = f"dig +short CNAME {subdomain}"
        output = run_command(dig_cmd, f"Checking CNAME for {subdomain}")
        
        if output and output.strip():
            cnames = [cname.strip().rstrip('.') for cname in output.split('\n') if cname.strip()]
            for cname in cnames:
                result = f"{subdomain} -> {cname}"
                print(f"✓ {result}")
                cname_results.append(result)
    
    # ذخیره نتایج CNAME
    output_file = os.path.join(output_dir, "cnames.txt")
    if cname_results:
        with open(output_file, 'w') as f:
            for result in cname_results:
                f.write(f"{result}\n")
        
        print(f"\n✓ Found {len(cname_results)} CNAME records")
        print(f"✓ Results saved to: {output_file}")
        return output_file, output_dir
    else:
        print("\n✗ No CNAME records found")
        return None, output_dir

class SubdomainTakeoverChecker:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # لیست سرویس‌های مستعد takeover
        self.vulnerable_services = {
            'github.io': {'name': 'GitHub Pages', 'signatures': ['there isnt a github pages site here', 'project not found']},
            'herokuapp.com': {'name': 'Heroku', 'signatures': ['no such app', 'heroku']},
            's3.amazonaws.com': {'name': 'AWS S3', 'signatures': ['no such bucket', 'the specified bucket does not exist']},
            'cloudfront.net': {'name': 'AWS CloudFront', 'signatures': ['error', 'not found']},
            'azurewebsites.net': {'name': 'Azure Web Apps', 'signatures': ['microsoft azure app service', '404']},
            'blob.core.windows.net': {'name': 'Azure Blob Storage', 'signatures': ['the specified blob does not exist']},
            'firebaseapp.com': {'name': 'Firebase', 'signatures': ['firebase hosting setup', 'project not found']},
            'web.app': {'name': 'Firebase', 'signatures': ['firebase hosting setup']},
            'netlify.app': {'name': 'Netlify', 'signatures': ['not found', 'netlify']},
            'vercel.app': {'name': 'Vercel', 'signatures': ['deployment not found']},
            'onrender.com': {'name': 'Render', 'signatures': []},
        }

    def get_cname(self, subdomain):
        """دریافت CNAME یک ساب‌دامین"""
        try:
            answers = dns.resolver.resolve(subdomain, 'CNAME')
            cnames = [str(rdata.target).rstrip('.') for rdata in answers]
            return cnames
        except:
            return []

    def check_http_response(self, subdomain):
        """بررسی پاسخ HTTP ساب‌دامین"""
        try:
            response = self.session.get(f"http://{subdomain}", timeout=10, verify=False)
            return {
                'status': response.status_code,
                'content': response.text.lower(),
                'headers': dict(response.headers)
            }
        except requests.exceptions.SSLError:
            try:
                response = self.session.get(f"https://{subdomain}", timeout=10, verify=False)
                return {
                    'status': response.status_code,
                    'content': response.text.lower(),
                    'headers': dict(response.headers)
                }
            except Exception as e:
                return {'error': f"HTTPS Error: {str(e)}"}
        except Exception as e:
            return {'error': f"HTTP Error: {str(e)}"}

    def check_takeover(self, subdomain, cname_target):
        """بررسی takeover برای یک ساب‌دامین و CNAME"""
        result = {
            'subdomain': subdomain,
            'cname_target': cname_target,
            'vulnerable_service': None,
            'evidence': [],
            'is_vulnerable': False,
            'confidence': 'low'
        }
        
        # بررسی اینکه CNAME به کدام سرویس اشاره می‌کند
        for service_domain, service_info in self.vulnerable_services.items():
            if service_domain in cname_target:
                result['vulnerable_service'] = service_info['name']
                
                # بررسی پاسخ HTTP
                http_result = self.check_http_response(subdomain)
                
                if 'error' in http_result:
                    result['evidence'].append(f"Connection error: {http_result['error']}")
                    result['is_vulnerable'] = True
                    result['confidence'] = 'medium'
                else:
                    # بررسی status code
                    if http_result['status'] in [404, 403, 500, 503]:
                        result['evidence'].append(f"Status code: {http_result['status']}")
                        result['is_vulnerable'] = True
                        result['confidence'] = 'medium'
                    
                    # بررسی محتوا برای الگوهای خطا
                    content = http_result['content']
                    for signature in service_info['signatures']:
                        if signature in content:
                            result['evidence'].append(f"Content pattern: {signature}")
                            result['is_vulnerable'] = True
                            result['confidence'] = 'high'
                
                break
        
        return result

    def check_from_file(self, input_file):
        """بررسی takeover از فایل CNAME"""
        if not os.path.isfile(input_file):
            print(f"File not found: {input_file}")
            return []
        
        # خواندن CNAMEها از فایل
        cname_entries = []
        with open(input_file, 'r') as f:
            for line in f:
                if '->' in line:
                    parts = line.strip().split('->')
                    if len(parts) == 2:
                        subdomain = parts[0].strip()
                        cname_target = parts[1].strip()
                        cname_entries.append((subdomain, cname_target))
        
        if not cname_entries:
            print("No CNAME entries found in the file!")
            return []
        
        print(f"Found {len(cname_entries)} CNAME entries to check")
        
        # بررسی همه entries
        results = []
        for subdomain, cname_target in cname_entries:
            print(f"Checking: {subdomain} -> {cname_target}")
            result = self.check_takeover(subdomain, cname_target)
            results.append(result)
            
            if result['is_vulnerable']:
                print(f"🚨 POTENTIAL TAKEOVER: {subdomain} (Confidence: {result['confidence']})")
            else:
                print(f"✓ No takeover detected: {subdomain}")
        
        return results

    def save_results(self, results, output_dir):
        """ذخیره نتایج در پوشه خروجی"""
        # فایل JSON کامل
        json_output = os.path.join(output_dir, "takeover_results.json")
        vulnerable_count = sum(1 for r in results if r['is_vulnerable'])
        
        with open(json_output, 'w', encoding='utf-8') as f:
            json.dump({
                'metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'total_checked': len(results),
                    'vulnerable_count': vulnerable_count
                },
                'results': results
            }, f, indent=2, ensure_ascii=False)
        
        # فایل متنی فقط ساب‌دامین‌های آسیب‌پذیر
        vulnerable_output = os.path.join(output_dir, "vulnerable_subdomains.txt")
        with open(vulnerable_output, 'w', encoding='utf-8') as f:
            f.write("VULNERABLE SUBDOMAINS - POTENTIAL TAKEOVER\n")
            f.write("=" * 50 + "\n")
            f.write(f"Generated at: {datetime.now().isoformat()}\n")
            f.write(f"Total vulnerable: {vulnerable_count}\n")
            f.write("=" * 50 + "\n\n")
            
            for result in results:
                if result['is_vulnerable']:
                    f.write(f"Subdomain: {result['subdomain']}\n")
                    f.write(f"CNAME Target: {result['cname_target']}\n")
                    f.write(f"Service: {result['vulnerable_service']}\n")
                    f.write(f"Confidence: {result['confidence']}\n")
                    for evidence in result['evidence']:
                        f.write(f"Evidence: {evidence}\n")
                    f.write("-" * 30 + "\n")
        
        print(f"\n✓ Full results saved to: {json_output}")
        print(f"✓ Vulnerable subdomains saved to: {vulnerable_output}")
        print(f"✓ Total vulnerable: {vulnerable_count}")

def detect_takeover():
    """تشخیص Subdomain Takeover"""
    print("\n" + "=" * 60)
    print("DETECT SUBDOMAIN TAKEOVER")
    print("=" * 60)
    
    # ایجاد پوشه خروجی
    output_dir = create_output_directory()
    print(f"Output directory: {output_dir}")
    
    # دریافت فایل ورودی
    input_file = input("Enter CNAME file path (default: use latest results): ").strip()
    if not input_file:
        # یافتن آخرین فایل cnames.txt
        results_dir = "results"
        if not os.path.exists(results_dir):
            print("No results directory found! Please run CNAME check first.")
            return None, None
        
        # پیدا کردن آخرین پوشه اسکن
        scan_folders = [f for f in os.listdir(results_dir) if f.startswith("scan_") and os.path.isdir(os.path.join(results_dir, f))]
        if not scan_folders:
            print("No scan folders found! Please run CNAME check first.")
            return None, None
        
        latest_scan = max(scan_folders)
        input_file = os.path.join(results_dir, latest_scan, "cnames.txt")
    
    if not os.path.isfile(input_file):
        print(f"File not found: {input_file}")
        return None, None
    
    # اجرای بررسی
    checker = SubdomainTakeoverChecker()
    results = checker.check_from_file(input_file)
    
    # ذخیره نتایج
    if results:
        checker.save_results(results, output_dir)
        
        # نمایش خلاصه
        vulnerable = [r for r in results if r['is_vulnerable']]
        if vulnerable:
            print("\n🚨 VULNERABLE SUBDOMAINS:")
            for result in vulnerable:
                print(f"- {result['subdomain']} -> {result['cname_target']}")
                print(f"  Service: {result['vulnerable_service']}")
                print(f"  Confidence: {result['confidence']}")
                for evidence in result['evidence']:
                    print(f"  Evidence: {evidence}")
                print()
    
    return results, output_dir

def main():
    """تابع اصلی"""
    show_banner()
    
    # ایجاد پوشه results اصلی
    os.makedirs("results", exist_ok=True)
    
    while True:
        choice = show_main_menu()
        
        if choice == '0':
            print("Goodbye!")
            break
        elif choice == '1':
            subdomains, output_dir = subdomain_enumeration()
            if output_dir:
                print(f"\nScan completed! Results saved in: {output_dir}")
        elif choice == '2':
            cname_file, output_dir = check_cnames()
            if output_dir:
                print(f"\nCNAME check completed! Results saved in: {output_dir}")
        elif choice == '3':
            results, output_dir = detect_takeover()
            if output_dir:
                print(f"\nTakeover detection completed! Results saved in: {output_dir}")
        elif choice == '4':
            print("Returning to main menu...")
            continue
        elif choice == '5':
            show_help()
        else:
            print("Invalid choice! Please try again.")
        
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()
