import json
from datetime import datetime

with open('direct_api_jobs.json', 'r', encoding='utf-8') as f:
    jobs = json.load(f)

# Sort jobs by date descending
jobs.sort(key=lambda x: x['Date'], reverse=True)

with open('internships_report_v2.md', 'w', encoding='utf-8') as f:
    f.write("# 🚀 Top 50+ Internships (Directly Sourced from ATS APIs)\n\n")
    f.write("*Sourced by directly polling Greenhouse and Lever APIs for top tech companies. NO GitHub datasets or major job boards were used.*\n\n")
    
    us_jobs = []
    intl_jobs = []
    
    for j in jobs:
        loc = j['Location'].lower()
        if 'us' in loc or 'united states' in loc or 'america' in loc or ',' in loc or 'remote' in loc:
            # simple heuristic, cities often have commas like "San Francisco, CA"
            if 'canada' not in loc and 'uk' not in loc and 'london' not in loc and 'germany' not in loc and 'india' not in loc and 'australia' not in loc:
                us_jobs.append(j)
            else:
                intl_jobs.append(j)
        else:
            # maybe international or unclassified
            intl_jobs.append(j)
            
    f.write(f"## 🇺🇸 US-Based or Remote Internships ({len(us_jobs)})\n\n")
    for j in us_jobs:
        f.write(f"- **{j['Company']}** - {j['Role']} ({j['Location']})\n  - **Date Posted:** {j['Date']}\n  - **Link:** {j['Link']}\n\n")

    if intl_jobs:
        f.write(f"## 🌍 International/Other Internships ({len(intl_jobs)})\n\n")
        for j in intl_jobs:
            f.write(f"- **{j['Company']}** - {j['Role']} ({j['Location']})\n  - **Date Posted:** {j['Date']}\n  - **Link:** {j['Link']}\n\n")

print(f"Generated report with {len(us_jobs)} US and {len(intl_jobs)} International jobs.")
