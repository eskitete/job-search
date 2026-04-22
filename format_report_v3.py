import json

with open('direct_api_filtered_jobs.json', 'r', encoding='utf-8') as f:
    jobs = json.load(f)

# Sort jobs descending by Date
jobs.sort(key=lambda x: x['Date'], reverse=True)

cyber_keywords = ['cyber', 'security', 'infosec', 'appsec', 'pentest', 'vulnerability']

cyber_jobs = []
other_jobs = []

for j in jobs:
    title = j['Role'].lower()
    company = j['Company'].lower()
    
    if any(k in title for k in cyber_keywords) or any(k in company for k in cyber_keywords):
        cyber_jobs.append(j)
    else:
        other_jobs.append(j)

with open('internships_report_v3.md', 'w', encoding='utf-8') as f:
    f.write("# 🚀 Top 50+ Internships (Filtered: No Masters/PhD Only)\n\n")
    f.write("*Sourced from ATS APIs directly. Roles strictly requiring a Master's or Ph.D. have been parsed out using the raw job descriptions.*\n\n")
    
    # helper for location filtering
    def render_section(section_jobs, title):
        us_jobs = []
        intl_jobs = []
        for j in section_jobs:
            loc = j['Location'].lower()
            if 'us' in loc or 'united states' in loc or 'america' in loc or ',' in loc or 'remote' in loc:
                if 'canada' not in loc and 'uk' not in loc and 'london' not in loc and 'germany' not in loc and 'india' not in loc and 'australia' not in loc:
                    us_jobs.append(j)
                else:
                    intl_jobs.append(j)
            else:
                intl_jobs.append(j)
                
        f.write(f"## {title}\n\n")
        f.write(f"### 🇺🇸 US-Based or Remote ({len(us_jobs)})\n\n")
        for j in us_jobs:
            f.write(f"- **{j['Company']}** - {j['Role']} ({j['Location']})\n  - **Date Posted:** {j['Date']}\n  - **Link:** {j['Link']}\n\n")
            
        if intl_jobs:
            f.write(f"### 🌍 International/Other ({len(intl_jobs)})\n\n")
            for j in intl_jobs:
                f.write(f"- **{j['Company']}** - {j['Role']} ({j['Location']})\n  - **Date Posted:** {j['Date']}\n  - **Link:** {j['Link']}\n\n")

    render_section(cyber_jobs, "🛡️ Cybersecurity Internships")
    f.write("---\n\n")
    render_section(other_jobs, "💻 Other Internships (Embedded, Fintech, ML, SWE)")
    
print(f"Generated report: {len(cyber_jobs)} Cyber jobs, {len(other_jobs)} Other jobs.")
