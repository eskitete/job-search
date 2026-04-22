import urllib.request
import json
import time

apis = [
    "https://remotive.com/api/remote-jobs?category=software-dev",
    "https://www.arbeitnow.com/api/job-board-api"
]

keywords = ['intern', 'internship', 'co-op', 'student']
roles = ['cyber', 'security', 'embedded', 'fintech', 'ai', 'machine learning', 'data', 'hardware', 'it ', 'system']

valid_jobs = []

for url in apis:
    print(f"Fetching from {url}...")
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode('utf-8'))
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        continue

    # parsing based on API structure
    if 'remotive' in url:
        jobs = data.get('jobs', [])
        for j in jobs:
            title = j.get('title', '').lower()
            if any(k in title for k in keywords):
                if any(r in title for r in roles) or 'software' in title:
                    valid_jobs.append({
                        "Company": j.get('company_name', 'Unknown'),
                        "Role": j.get('title', ''),
                        "Location": j.get('candidate_required_location', 'Remote'),
                        "Date": j.get('publication_date', 'Recent').split('T')[0],
                        "Link": j.get('url', ''),
                        "Source": "Remotive API"
                    })
    elif 'arbeitnow' in url:
        jobs = data.get('data', [])
        for j in jobs:
            title = j.get('title', '').lower()
            if any(k in title for k in keywords):
                if any(r in title for r in roles) or 'software' in title:
                    valid_jobs.append({
                        "Company": j.get('company_name', 'Unknown'),
                        "Role": j.get('title', ''),
                        "Location": j.get('location', 'Unknown'),
                        "Date": j.get('created_at', 'Recent'),
                        "Link": j.get('url', ''),
                        "Source": "Arbeitnow API"
                    })

print(f"Found {len(valid_jobs)} internship jobs from Open APIs.")
with open('api_jobs.json', 'w', encoding='utf-8') as f:
    json.dump(valid_jobs, f, indent=4)
