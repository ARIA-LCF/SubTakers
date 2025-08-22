# ابزار جامع شناسایی ساب‌دامین و تشخیص Subdomain Takeover

## 📖 فهرست مطالب
- [معرفی](#معرفی)
- [امکانات](#امکانات)
- [نصب و راه‌اندازی](#نصب-و-راه‌اندازی)
- [نحوه استفاده](#نحوه-استفاده)
- [توضیح Subdomain Takeover](#توضیح-subdomain-takeover)
- [سرویس‌های مستعد Takeover](#سرویس‌های-مستعد-takeover)
- [مثال‌ها](#مثال‌ها)
- [خروجی‌ها](#خروجی‌ها)
- [محدودیت‌ها](#محدودیت‌ها)

## 🌟 معرفی

ابزار جامع شناسایی ساب‌دامین و تشخیص Subdomain Takeover یک اسکریپت پایتونی قدرتمند است که به صورت خودکار فرآیندهای زیر را انجام می‌دهد:

1. **شناسایی ساب‌دامین‌ها** با استفاده از چندین ابزار معروف
2. **بررسی رکوردهای CNAME** برای ساب‌دامین‌های کشف شده
3. **تشخیص آسیب‌پذیری‌های Subdomain Takeover** به صورت هوشمند

این ابزار برای متخصصین امنیت سایبری، محققین bug bounty و تیم‌های penetration testing طراحی شده است.

## 🚀 امکانات

- 🔍 **شناسایی ساب‌دامین** با ۶ ابزار مختلف (Subfinder, Assetfinder, Amass, Sublist3r, Findomain, Knockpy)
- 📋 **بررسی خودکار CNAME** برای تمام ساب‌دامین‌های کشف شده
- 🚨 **تشخیص هوشمند Takeover** با الگوریتم چندمرحله‌ای
- 📊 **گزارش‌گیری جامع** در فرمت‌های مختلف
- ⚡ **پردازش موازی** برای افزایش سرعت
- 🎯 **رتبه‌بندی اطمینان** (Low/Medium/High) برای هر تشخیص
- 📁 **مدیریت خودکار فایل‌ها** با ساختار سازمان‌یافته

## 🔧 نصب و راه‌اندازی

### prerequisites نیازمندی‌ها

```bash
# نصب Python 3
sudo apt install python3 python3-pip

# نصب کتابخانه‌های مورد نیاز
pip3 install requests dnspython

# نصب ابزارهای شناسایی ساب‌دامین (اختیاری - ابزار به صورت خودکار نصب می‌کند)
sudo apt install golang
```

### نصب ابزار

```bash
# دانلود اسکریپت
git clone https://github.com/ARIA-LCF/SubTakers.git
cd SubTakers

# اجرای ابزار
python3 main.py
```

## 🎮 نحوه استفاده

### منوی اصلی

```
1. Find Subdomains       - شناسایی ساب‌دامین‌ها
2. Check CNAME Records   - بررسی رکوردهای CNAME
3. Detect Subdomain Takeover - تشخیص آسیب‌پذیری Takeover
4. Back to Previous Menu - بازگشت به منوی قبلی
5. Help & Information    - راهنما و اطلاعات
0. Exit                  - خروج
```

### مراحل کار

1. **گزینه 1 را انتخاب کنید** برای شناسایی ساب‌دامین‌ها
   - وارد کردن مسیر فایل domains.txt یا یک دامنه خاص
   - ابزار به صورت خودکار ساب‌دامین‌ها را پیدا می‌کند

2. **گزینه 2 را انتخاب کنید** برای بررسی CNAME
   - استفاده از فایل خروجی مرحله قبل
   - ذخیره نتایج در فایل cnames.txt

3. **گزینه 3 را انتخاب کنید** برای تشخیص Takeover
   - تحلیل خودکار CNAME‌های پیدا شده
   - تولید گزارش کامل در takeover_results.json

## 🔍 توضیح Subdomain Takeover

### چیست؟ Subdomain Takeover

Subdomain Takeover یک آسیب‌پذیری امنیتی است که زمانی رخ می‌دهد که یک ساب‌دامین به یک سرویس third-party (مثل GitHub Pages, Heroku, AWS S3) اشاره می‌کند، اما آن سرویس حذف یا غیرفعال شده است. این امر به attacker اجازه می‌دهد تا ساب‌دامین را تصاحب کند.

### چگونه اتفاق می‌افتد؟

1. 🏢 یک شرکت از سرویس cloud استفاده می‌کند
2. 🔗 ساب‌دامین را به سرویس متصل می‌کند (از طریق CNAME)
3. 🗑️ سرویس cloud حذف یا غیرفعال می‌شود
4. 👨‍💻 attacker سرویس را دوباره ایجاد می‌کند
5. 🎯 attacker کنترل ساب‌دامین را به دست می‌آورد

### خطرات

- 📧 ارسال ایمیل‌های جعلی
- 🍪 سرقت کوکی‌ها و sessionها
- 🔐 فیشینگ اطلاعات حساس
- 📊 جعل هویت سازمان

## 🎯 سرویس‌های مستعد Takeover

| سرویس | دامنه | سطح خطر |
|-------|-------|----------|
| GitHub Pages | `*.github.io` | بالا |
| Heroku | `*.herokuapp.com` | بالا |
| AWS S3 | `*.s3.amazonaws.com` | بالا |
| Firebase | `*.firebaseapp.com`, `*.web.app` | متوسط |
| Azure Web Apps | `*.azurewebsites.net` | متوسط |
| Netlify | `*.netlify.app` | متوسط |
| Vercel | `*.vercel.app` | متوسط |
| CloudFront | `*.cloudfront.net` | متوسط |

## 📋 مثال‌ها

### مثال ۱: شناسایی ساب‌دامین

```bash
# وارد کردن دامنه هدف
Enter the target domain (e.g., example.com): example.com

# اجرای شناسایی
✓ Found 154 subdomains for example.com
✓ Results saved to: results/subdomains_example.com_20231201_143022.txt
```

### مثال ۲: تشخیص Takeover

```json
{
  "subdomain": "cdn.example.com",
  "cname_target": "example.s3.amazonaws.com",
  "vulnerable_service": "AWS S3",
  "evidence": [
    "Status code: 404",
    "Content pattern: no such bucket"
  ],
  "is_vulnerable": true,
  "confidence": "high"
}
```

## 📊 خروجی‌ها

### فایل‌های تولید شده

1. **subdomains_*.txt** - لیست ساب‌دامین‌های کشف شده
2. **cnames.txt** - رکوردهای CNAME پیدا شده
3. **takeover_results.json** - گزارش کامل آسیب‌پذیری‌ها

### فرمت خروجی JSON

```json
{
  "metadata": {
    "generated_at": "2023-12-01T14:30:22",
    "total_checked": 45,
    "vulnerable_count": 3
  },
  "results": [
    {
      "subdomain": "test.example.com",
      "cname_target": "test.herokuapp.com",
      "vulnerable_service": "Heroku",
      "evidence": ["Status code: 404"],
      "is_vulnerable": true,
      "confidence": "medium"
    }
  ]
}
```

## ⚠️ محدودیت‌ها

- 🔍 ممکن است برخی ساب‌دامین‌های پنهان شناسایی نشوند
- ⏱️ بررسی کامل ممکن است زمان‌بر باشد
- 🌐 برخی سرویس‌ها ممکن است blocked شده باشند
- 🤖 تشخیص اتوماتیک ممکن است false-positive داشته باشد

## 📞 پشتیبانی و ارتباط

برای سوالات، پیشنهادات و گزارش باگ‌ها می‌توانید از طریق کانال تلگرام با ما در ارتباط باشید:

**کانال تلگرام: [@LCFkie](https://t.me/LCFkie)**

---

# Comprehensive Subdomain Enumeration and Takeover Detection Tool

## 📖 Table of Contents
- [Introduction](#introduction)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Subdomain Takeover Explained](#subdomain-takeover-explained)
- [Vulnerable Services](#vulnerable-services)
- [Examples](#examples)
- [Outputs](#outputs)
- [Limitations](#limitations)

## 🌟 Introduction

The Comprehensive Subdomain Enumeration and Takeover Detection Tool is a powerful Python script that automates the following processes:

1. **Subdomain enumeration** using multiple renowned tools
2. **CNAME record analysis** for discovered subdomains
3. **Intelligent Subdomain Takeover vulnerability detection**

This tool is designed for cybersecurity professionals, bug bounty researchers, and penetration testing teams.

## 🚀 Features

- 🔍 **Subdomain discovery** with 6 different tools (Subfinder, Assetfinder, Amass, Sublist3r, Findomain, Knockpy)
- 📋 **Automatic CNAME checking** for all discovered subdomains
- 🚨 **Smart Takeover detection** with multi-stage algorithm
- 📊 **Comprehensive reporting** in various formats
- ⚡ **Parallel processing** for increased speed
- 🎯 **Confidence rating** (Low/Medium/High) for each detection
- 📁 **Automatic file management** with organized structure

## 🔧 Installation

### Prerequisites

```bash
# Install Python 3
sudo apt install python3 python3-pip

# Install required libraries
pip3 install requests dnspython

# Install subdomain enumeration tools (Optional - tool auto-installs)
sudo apt install golang
```

### Tool Installation

```bash
# Download the script
git clone https://github.com/your-repo/subdomain-takeover-tool.git
cd subdomain-takeover-tool

# Run the tool
python3 subdomain_tool.py
```

## 🎮 Usage

### Main Menu

```
1. Find Subdomains       - Discover subdomains
2. Check CNAME Records   - Analyze CNAME records
3. Detect Subdomain Takeover - Detect takeover vulnerabilities
4. Back to Previous Menu - Return to previous menu
5. Help & Information    - Help and information
0. Exit                  - Exit
```

### Workflow

1. **Select Option 1** for subdomain enumeration
   - Enter path to domains.txt file or a specific domain
   - Tool automatically discovers subdomains

2. **Select Option 2** for CNAME checking
   - Use output file from previous step
   - Save results to cnames.txt

3. **Select Option 3** for Takeover detection
   - Automatic analysis of found CNAMEs
   - Generate comprehensive report in takeover_results.json

## 🔍 Subdomain Takeover Explained

### What is Subdomain Takeover?

Subdomain Takeover is a security vulnerability that occurs when a subdomain points to a third-party service (like GitHub Pages, Heroku, AWS S3) that has been deleted or deactivated. This allows an attacker to claim the subdomain.

### How does it happen?

1. 🏢 A company uses a cloud service
2. 🔗 Connects subdomain to the service (via CNAME)
3. 🗑️ Cloud service gets deleted or deactivated
4. 👨‍💻 Attacker recreates the service
5. 🎯 Attacker gains control of the subdomain

### Risks

- 📧 Sending fake emails
- 🍪 Stealing cookies and sessions
- 🔐 Phishing sensitive information
- 📊 Organization identity spoofing

## 🎯 Vulnerable Services

| Service | Domain | Risk Level |
|---------|--------|------------|
| GitHub Pages | `*.github.io` | High |
| Heroku | `*.herokuapp.com` | High |
| AWS S3 | `*.s3.amazonaws.com` | High |
| Firebase | `*.firebaseapp.com`, `*.web.app` | Medium |
| Azure Web Apps | `*.azurewebsites.net` | Medium |
| Netlify | `*.netlify.app` | Medium |
| Vercel | `*.vercel.app` | Medium |
| CloudFront | `*.cloudfront.net` | Medium |

## 📋 Examples

### Example 1: Subdomain Enumeration

```bash
# Enter target domain
Enter the target domain (e.g., example.com): example.com

# Run enumeration
✓ Found 154 subdomains for example.com
✓ Results saved to: results/subdomains_example.com_20231201_143022.txt
```

### Example 2: Takeover Detection

```json
{
  "subdomain": "cdn.example.com",
  "cname_target": "example.s3.amazonaws.com",
  "vulnerable_service": "AWS S3",
  "evidence": [
    "Status code: 404",
    "Content pattern: no such bucket"
  ],
  "is_vulnerable": true,
  "confidence": "high"
}
```

## 📊 Outputs

### Generated Files

1. **subdomains_*.txt** - List of discovered subdomains
2. **cnames.txt** - Found CNAME records
3. **takeover_results.json** - Complete vulnerability report

### JSON Output Format

```json
{
  "metadata": {
    "generated_at": "2023-12-01T14:30:22",
    "total_checked": 45,
    "vulnerable_count": 3
  },
  "results": [
    {
      "subdomain": "test.example.com",
      "cname_target": "test.herokuapp.com",
      "vulnerable_service": "Heroku",
      "evidence": ["Status code: 404"],
      "is_vulnerable": true,
      "confidence": "medium"
    }
  ]
}
```

## ⚠️ Limitations

- 🔍 Some hidden subdomains might not be detected
- ⏱️ Complete scanning might be time-consuming
- 🌐 Some services might be blocked
- 🤖 Automatic detection might have false-positives

## 📞 Support and Contact

For questions, suggestions, and bug reports, you can reach us through our Telegram channel:

**Telegram Channel: [@LCFkie](https://t.me/LCFkie)**

---

**توسعه داده شده توسط تیم LCFkie** | **Developed by LCFkie Team**
