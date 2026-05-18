#!/usr/bin/env python3

import requests
from bs4 import BeautifulSoup
import re
import csv
from datetime import datetime

APPLE_SECURITY_URL = "https://support.apple.com/en-us/100100"

OUTPUT_FILE = f"apple_macos_cves_{datetime.now().strftime('%Y-%m-%d')}.csv"


def fetch_page(url):
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    return response.text


def extract_macos_links(html):
    soup = BeautifulSoup(html, "html.parser")

    links = []

    for a in soup.find_all("a", href=True):
        text = a.get_text(strip=True)
        href = a["href"]

        if "macOS" in text and ("security" in text.lower() or "About the security content" in text):
            if href.startswith("/"):
                href = "https://support.apple.com" + href

            links.append({
                "title": text,
                "url": href
            })

    return links


def extract_cves_from_security_page(url, title):
    html = fetch_page(url)
    soup = BeautifulSoup(html, "html.parser")

    page_text = soup.get_text("\n", strip=True)

    cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", page_text)))

    rows = []

    for cve in cves:
        rows.append({
            "apple_update_title": title,
            "apple_url": url,
            "cve": cve
        })

    return rows


def write_csv(rows):
    fieldnames = [
        "apple_update_title",
        "apple_url",
        "cve"
    ]

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main():
    print("Fetching Apple security updates page...")
    html = fetch_page(APPLE_SECURITY_URL)

    print("Finding macOS security update links...")
    macos_links = extract_macos_links(html)

    print(f"Found {len(macos_links)} macOS-related links")

    all_rows = []

    for item in macos_links:
        print(f"Scraping: {item['title']}")
        try:
            rows = extract_cves_from_security_page(item["url"], item["title"])
            all_rows.extend(rows)
        except Exception as e:
            print(f"Failed to scrape {item['url']}: {e}")

    print(f"Writing {len(all_rows)} CVE rows to {OUTPUT_FILE}")
    write_csv(all_rows)

    print("Done")


if __name__ == "__main__":
    main()
