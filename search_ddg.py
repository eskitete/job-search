import json
import time
from duckduckgo_search import DDGS

platforms = ["site:jobs.lever.co", "site:boards.greenhouse.io", "site:jobs.ashbyhq.com", "site:workable.com"]
keywords = [
    '"cybersecurity intern"',
    '"security intern"',
    '"embedded intern"',
    '"fintech intern"',
    '"machine learning intern"',
    '"hardware intern"'
]

results_all = []
unique_urls = set()

print("Starting DDG search...")
try:
    with DDGS() as ddgs:
        for plat in platforms:
            for kw in keywords:
                query = f'{plat} {kw}'
                print(f"Searching: {query}")
                try:
                    results = list(ddgs.text(query, max_results=30, timelimit='w'))
                    for r in results:
                        href = r.get('href')
                        if href and href not in unique_urls:
                            unique_urls.add(href)
                            results_all.append(r)
                    time.sleep(1.5)
                except Exception as e:
                    print(f"Error for {query}: {e}")
except Exception as e:
    print(f"Global error: {e}")

print(f"Found {len(results_all)} unique jobs on ATS platforms past week.")

if len(results_all) < 50:
    print("Under 50 results. Expanding search to month...")
    try:
        with DDGS() as ddgs:
            for plat in platforms:
                query = f'{plat} internship (cybersecurity OR embedded OR fintech OR "machine learning")'
                print(f"Searching: {query}")
                try:
                    results = list(ddgs.text(query, max_results=40, timelimit='m'))
                    for r in results:
                        href = r.get('href')
                        if href and href not in unique_urls:
                            unique_urls.add(href)
                            results_all.append(r)
                    time.sleep(1.5)
                except Exception as e:
                    print(f"Error for {query}: {e}")
    except Exception as e:
        print(f"Global error: {e}")

with open('jobs_all.json', 'w') as f:
    json.dump(results_all, f, indent=4)

print(f"Total jobs collected: {len(results_all)}")
