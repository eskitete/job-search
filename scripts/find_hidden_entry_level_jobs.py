# add near imports
import argparse, os, pathlib, asyncio

# replace your `main()` and __main__ block with:
async def run(domains, out_dir):
    # existing body of your main() goes here
    # - use `domains` instead of hardcoded list
    # - write CSVs to `out_dir`
    ...

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--domains-file", default=os.getenv("DOMAINS_FILE", "config/domains.txt"))
    ap.add_argument("--out-dir", default=os.getenv("OUTPUT_DIR", "data"))
    args = ap.parse_args()

    # read domains (one per line, skip blanks/#)
    p = pathlib.Path(args.domains_file)
    domains = [ln.strip() for ln in p.read_text().splitlines() if ln.strip() and not ln.strip().startswith("#")]

    pathlib.Path(args.out_dir).mkdir(parents=True, exist_ok=True)
    asyncio.run(run(domains, args.out_dir))
