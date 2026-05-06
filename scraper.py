import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.options import Options
import time

class UniversalScraper:
    def __init__(self, url):
        self.url = url
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
        }

    # -------------------------
    # METHOD 1: Static Scraping
    # -------------------------
    def scrape_static(self):
        try:
            response = requests.get(self.url, headers=self.headers, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "lxml")
            return soup
        except Exception as e:
            print(f"[ERROR - STATIC] {e}")
            return None

    # -------------------------
    # METHOD 2: Dynamic Scraping (JS)
    # -------------------------
    def scrape_dynamic(self):
        try:
            options = Options()
            options.add_argument("--headless")
            options.add_argument("--disable-blink-features=AutomationControlled")

            driver = webdriver.Chrome(
                service=Service(ChromeDriverManager().install()),
                options=options
            )

            driver.get(self.url)
            time.sleep(5)  # wait for JS to load

            html = driver.page_source
            driver.quit()

            soup = BeautifulSoup(html, "lxml")
            return soup

        except Exception as e:
            print(f"[ERROR - DYNAMIC] {e}")
            return None

    # -------------------------
    # SMART SCRAPER
    # -------------------------
    def scrape(self):
        print(f"[INFO] Trying static scrape...")
        soup = self.scrape_static()

        if soup and len(soup.text.strip()) > 100:
            print("[SUCCESS] Static scrape worked")
            return soup

        print("[INFO] Falling back to dynamic scraping...")
        soup = self.scrape_dynamic()

        if soup:
            print("[SUCCESS] Dynamic scrape worked")
        else:
            print("[FAILED] Could not scrape site")

        return soup

    # -------------------------
    # GENERIC DATA EXTRACTOR
    # -------------------------
    def extract_all_text(self, soup):
        return soup.get_text(separator="\n", strip=True)

    def extract_links(self, soup):
        return [a.get("href") for a in soup.find_all("a", href=True)]

    def extract_images(self, soup):
        return [img.get("src") for img in soup.find_all("img", src=True)]


# -------------------------
# USAGE
# -------------------------
if __name__ == "__main__":
    url = input("Enter website URL: ")

    scraper = UniversalScraper(url)
    soup = scraper.scrape()

    if soup:
        print("\n--- PAGE TEXT ---")
        print(scraper.extract_all_text(soup)[:1000])

        print("\n--- LINKS ---")
        print(scraper.extract_links(soup)[:10])

        print("\n--- IMAGES ---")
        print(scraper.extract_images(soup)[:10])