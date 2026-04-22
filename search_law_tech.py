import urllib.request
import json
from datetime import datetime, timezone, timedelta
import ssl
import time
import re

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

# LegalTech & Law Firms that might use Greenhouse/Lever
companies = [
    'clio', 'everlaw', 'ironclad', 'disco', 'relativity', 'filevine', 'mycase',
    'smokeball', 'practicepanther', 'lexisnexis', 'thomsonreuters', 'imanage',
    'litera', 'lawpay', 'notarize', 'legalzoom', 'rocketlawyer', 'harbor',
    'opis', 'ontra', 'luceosolutions', 'contractpodai', 'agiloft', 'linksquares',
    'conga', 'icertis', 'kira', 'luminance', 'vlex', 'casetext', 'fastcase',
    # law firms the user might be interested in if they use these ATS
    'cooley', 'orrick', 'wsgr', 'goodwin', 'fenwick'
]

role_keywords = ['cyber', 'security', 'embedded', 'fintech', 'ai', 'machine learning', 'ml', 'hardware', 'it', 'infrastructure', 'systems', 'backend', 'data', 'software', 'tech']
intern_keywords = ['intern', 'internship', 'co-op', 'coop', 'student']

phd_master_patterns = [
    r'currently pursuing a ph\.?d\.?',
    r'ph\.?d\.? student',
    r'must be enrolled in a ph\.?d\.? program',
    r'must be enrolled in a master\'s program',
    r'currently pursuing a master\'s',
    r'ph\.?d\.? required',
    r'master\'s required'
]

found_jobs = []
now = datetime.now(timezone.utc)
ten_days_ago = now - timedelta(days=10)

def is_phd_master_only(description):
    desc_lower = description.lower()
    for pattern in phd_master_patterns:
        if re.search(pattern, desc_lower):
            if "bachelor" not in desc_lower and "bs/ms" not in desc_lower and "undergrad" not in desc_lower:
                return True
    return False

def check_greenhouse(company):
    url = f"https://boards-api.greenhouse.io/v1/boards/{company}/jobs?content=true"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, context=ctx, timeout=5) as response:
            data = json.loads(response.read().decode('utf-8'))
            jobs = data.get('jobs', [])
            for j in jobs:
                title = j.get('title', '').lower()
                if any(ik in title for ik in intern_keywords):
                    if any(rk in title for rk in role_keywords):
                        date_str = j.get('updated_at', '')
                        if date_str:
                            try:
                                post_date = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
                                if post_date >= ten_days_ago:
                                    desc_html = j.get('content', '')
                                    if desc_html and is_phd_master_only(desc_html):
                                        continue

                                    loc = j.get('location', {}).get('name', 'Unknown')
                                    found_jobs.append({
                                        'Company': company.capitalize(),
                                        'Role': j.get('title'),
                                        'Location': loc,
                                        'Date': post_date.strftime('%Y-%m-%d'),
                                        'Link': j.get('absolute_url'),
                                        'Source': 'Greenhouse'
                                    })
                            except:
                                pass
    except:
        pass

def check_lever(company):
    url = f"https://api.lever.co/v0/postings/{company}"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, context=ctx, timeout=5) as response:
            jobs = json.loads(response.read().decode('utf-8'))
            for j in jobs:
                title = j.get('text', '').lower()
                if any(ik in title for ik in intern_keywords):
                    if any(rk in title for rk in role_keywords):
                        created_at = j.get('createdAt')
                        if created_at:
                            post_date = datetime.fromtimestamp(created_at/1000.0, tz=timezone.utc)
                            if post_date >= ten_days_ago:
                                desc_html = j.get('descriptionPlain', j.get('description', ''))
                                if desc_html and is_phd_master_only(desc_html):
                                    continue

                                loc = j.get('categories', {}).get('location', 'Unknown')
                                found_jobs.append({
                                    'Company': company.capitalize(),
                                    'Role': j.get('text'),
                                    'Location': loc,
                                    'Date': post_date.strftime('%Y-%m-%d'),
                                    'Link': j.get('hostedUrl'),
                                    'Source': 'Lever'
                                })
    except:
        pass

print(f"Checking APIs for {len(companies)} LegalTech / Law firms...", flush=True)

for i, comp in enumerate(companies):
    if i % 10 == 0:
        print(f"Processed {i}/{len(companies)} companies...", flush=True)
    check_greenhouse(comp)
    check_lever(comp)

print(f"Jobs found from API: {len(found_jobs)}")

with open('law_api_jobs.json', 'w', encoding='utf-8') as f:
    json.dump(found_jobs, f, indent=4)
