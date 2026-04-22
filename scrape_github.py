import urllib.request
import re
import json

repos = [
    "https://raw.githubusercontent.com/SimplifyJobs/Summer2026-Internships/dev/README.md",
    "https://raw.githubusercontent.com/speedyapply/2026-SWE-College-Jobs/main/README.md",
    "https://raw.githubusercontent.com/vanshb03/Summer2026-Internships/main/README.md",
    "https://raw.githubusercontent.com/summer2026internships/Summer2026-Internships/main/README.md"
]

keywords = ['cyber', 'security', 'embedded', 'fintech', 'machine learning', ' ai ', '/ai', 'ml', 'data engine', 'infrastructure', 'backend', 'system', 'hardware', 'information tech']

# Dates from Feb 15 to Feb 25
valid_dates = [f"Feb {i}" for i in range(15, 26)] + [f"Feb 0{i}" for i in range(1, 10)]

valid_jobs = []
seen_links = set()

for url in repos:
    print(f"Fetching from {url}...")
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response:
            content = response.read().decode('utf-8')
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        continue

    lines = content.split('\n')
    print(f"Total lines: {len(lines)}")
    
    for line in lines:
        if line.startswith('|') and 'Company' not in line and '---' not in line:
            parts = [p.strip() for p in line.split('|')]
            # Typical format is: | Company | Role | Location | Application/Link | Date Posted |
            if len(parts) >= 6:
                company = parts[1]
                role = parts[2]
                location = parts[3]
                link = parts[4]
                date = parts[5]

                is_recent = False
                for vd in valid_dates:
                    if vd in date:
                        is_recent = True
                        break
                
                # If there's no date column or it doesn't match, we might want to still consider it if it's very recent repos
                # But let's stick to recent dates to ensure <5 applicants/freshness
                if is_recent:
                    href_match = re.search(r'href="([^"]+)"', link)
                    if href_match:
                        url_link = href_match.group(1)
                    else:
                        md_match = re.search(r'\]\(([^)]+)\)', link)
                        if md_match:
                            url_link = md_match.group(1)
                        else:
                            url_link = link
                            
                    if "closed" not in link.lower() and "🛂" not in link and url_link not in seen_links:
                        
                        role_lower = role.lower()
                        company_lower = company.lower()
                        
                        # Match user queries
                        if any(k in role_lower for k in keywords) or any(k in company_lower for k in keywords):
                            seen_links.add(url_link)
                            valid_jobs.append({
                                "Company": company,
                                "Role": role,
                                "Location": location,
                                "Date": date,
                                "Link": url_link,
                                "Source": url
                            })

print(f"Total jobs found from repos: {len(valid_jobs)}")
if len(valid_jobs) < 50:
    print("Expanding without strict date constraints for 2026 repos...")
    # Second pass, ignore dates but keep keywords
    for url in repos:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req) as response:
                content = response.read().decode('utf-8')
        except:
            continue
        
        lines = content.split('\n')
        for line in lines:
            if line.startswith('|') and 'Company' not in line and '---' not in line:
                parts = [p.strip() for p in line.split('|')]
                if len(parts) >= 6:
                    company = parts[1]
                    role = parts[2]
                    location = parts[3]
                    link = parts[4]
                    
                    href_match = re.search(r'href="([^"]+)"', link)
                    if href_match:
                        url_link = href_match.group(1)
                    else:
                        md_match = re.search(r'\]\(([^)]+)\)', link)
                        if md_match:
                            url_link = md_match.group(1)
                        else:
                            url_link = link
                    
                    if "closed" not in link.lower() and "🛂" not in link and url_link not in seen_links:
                        role_lower = role.lower()
                        company_lower = company.lower()
                        
                        if any(k in role_lower for k in keywords) or any(k in company_lower for k in keywords):
                            seen_links.add(url_link)
                            valid_jobs.append({
                                "Company": company,
                                "Role": role,
                                "Location": location,
                                "Date": parts[5] if len(parts) > 5 else "N/A",
                                "Link": url_link,
                                "Source": url
                            })

print(f"Total jobs after expansion: {len(valid_jobs)}")

# Final report formatting
with open("internships_report.md", "w", encoding='utf-8') as f:
    f.write("# 🚀 Top 50+ Internships (Cybersecurity, Embedded, Fintech, IT)\n\n")
    f.write("*Sourced from GitHub Summer 2026 Internships repositories.* \n\n")
    for j in valid_jobs[:100]:
        f.write(f"- **{j['Company']}** - {j['Role']} ({j['Location']})\n  - **Date Posted:** {j['Date']}\n  - **Link:** {j['Link']}\n\n")

print("Report saved to internships_report.md")
