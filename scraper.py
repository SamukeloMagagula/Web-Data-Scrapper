import os
import random
import time
import mimetypes
from pathlib import Path
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup
from curl_cffi import requests as cffi_requests
import undetected_chromedriver as uc
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:130.0) Gecko/20100101 Firefox/130.0",
]


def realistic_headers(user_agent: str) -> dict:
    return {
        "User-Agent": user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Cache-Control": "max-age=0",
    }


class StealthScraper:
    def __init__(self, url: str, proxy: str | None = None):
        self.url = url
        self.proxy = proxy  # e.g. "http://user:pass@host:port"
        self.user_agent = random.choice(USER_AGENTS)

    # ------------------------------------------------------------------
    # STATIC PATH — curl_cffi with browser TLS fingerprint
    # ------------------------------------------------------------------
    def scrape_static(self) -> BeautifulSoup | None:
        try:
            proxies = {"http": self.proxy, "https": self.proxy} if self.proxy else None
            response = cffi_requests.get(
                self.url,
                headers=realistic_headers(self.user_agent),
                impersonate="chrome131",   # mimics Chrome 131's JA3/TLS fingerprint
                timeout=15,
                proxies=proxies,
            )
            response.raise_for_status()
            soup = BeautifulSoup(response.content, "lxml")
            if self._looks_like_js_shell(soup) or self._looks_like_block_page(soup):
                return None
            return soup
        except Exception as e:
            print(f"[STATIC ERROR] {e}")
            return None

    @staticmethod
    def _looks_like_js_shell(soup: BeautifulSoup) -> bool:
        text = soup.get_text(strip=True).lower()
        markers = ["enable javascript", "please enable js", "you need to enable javascript"]
        if any(m in text for m in markers):
            return True
        if len(text) < 200 and len(soup.find_all("script")) > 3:
            return True
        return False

    @staticmethod
    def _looks_like_block_page(soup: BeautifulSoup) -> bool:
        text = soup.get_text(strip=True).lower()
        block_markers = [
            "cloudflare", "checking your browser", "attention required",
            "access denied", "request blocked", "are you a human",
            "verify you are human", "ddos protection",
        ]
        # Title-only check is more reliable than full text
        title = (soup.title.string or "").lower() if soup.title else ""
        return any(m in title for m in block_markers)

    # ------------------------------------------------------------------
    # DYNAMIC PATH — undetected-chromedriver
    # ------------------------------------------------------------------
    def scrape_dynamic(self, scroll: bool = True) -> BeautifulSoup | None:
        options = uc.ChromeOptions()
        options.add_argument("--headless=new")
        options.add_argument("--disable-blink-features=AutomationControlled")
        options.add_argument(f"--user-agent={self.user_agent}")
        options.add_argument("--window-size=1920,1080")
        if self.proxy:
            options.add_argument(f"--proxy-server={self.proxy}")

        driver = None
        try:
            driver = uc.Chrome(options=options, version_main=None)
            driver.get(self.url)

            WebDriverWait(driver, 20).until(
                lambda d: d.execute_script("return document.readyState") == "complete"
            )
            self._human_pause(1.5, 3.0)

            if scroll:
                self._auto_scroll(driver)

            html = driver.page_source
            return BeautifulSoup(html, "lxml")
        except Exception as e:
            print(f"[DYNAMIC ERROR] {e}")
            return None
        finally:
            if driver is not None:
                try:
                    driver.quit()
                except Exception:
                    pass

    @staticmethod
    def _human_pause(lo: float, hi: float) -> None:
        time.sleep(random.uniform(lo, hi))

    def _auto_scroll(self, driver, max_scrolls: int = 30) -> None:
        """Scroll to bottom in chunks, waiting for new content to load."""
        last_height = driver.execute_script("return document.body.scrollHeight")
        for _ in range(max_scrolls):
            driver.execute_script(
                "window.scrollBy(0, window.innerHeight * 0.8);"
            )
            self._human_pause(0.6, 1.4)
            new_height = driver.execute_script("return document.body.scrollHeight")
            if new_height == last_height:
                # one more nudge in case of a slow loader
                self._human_pause(1.0, 2.0)
                final_height = driver.execute_script("return document.body.scrollHeight")
                if final_height == new_height:
                    break
            last_height = new_height

    # ------------------------------------------------------------------
    # SMART ENTRY POINT
    # ------------------------------------------------------------------
    def scrape(self) -> BeautifulSoup | None:
        print("[INFO] Trying stealth static scrape...")
        soup = self.scrape_static()
        if soup is not None:
            print("[OK] Static scrape succeeded")
            return soup

        print("[INFO] Falling back to undetected browser...")
        soup = self.scrape_dynamic()
        if soup is not None:
            print("[OK] Dynamic scrape succeeded")
        else:
            print("[FAIL] Could not retrieve page")
        return soup

    # ------------------------------------------------------------------
    # IMAGE EXTRACTION (handles lazy loading)
    # ------------------------------------------------------------------
    IMG_ATTRS = ("src", "data-src", "data-lazy-src", "data-original", "data-actualsrc")

    def extract_images(self, soup: BeautifulSoup) -> list[str]:
        urls: set[str] = set()

        for img in soup.find_all("img"):
            for attr in self.IMG_ATTRS:
                val = img.get(attr)
                if val:
                    urls.add(self._absolute(val))
                    break  # take the first non-empty source per img

            # srcset: pick the largest candidate
            srcset = img.get("srcset") or img.get("data-srcset")
            if srcset:
                best = self._pick_largest_from_srcset(srcset)
                if best:
                    urls.add(self._absolute(best))

        # CSS background-image scraped from inline styles
        for el in soup.find_all(style=True):
            style = el["style"]
            if "background-image" in style and "url(" in style:
                start = style.find("url(") + 4
                end = style.find(")", start)
                if end > start:
                    raw = style[start:end].strip(" '\"")
                    if raw:
                        urls.add(self._absolute(raw))

        # filter junk
        return [u for u in urls if self._is_real_image(u)]

    def _absolute(self, href: str) -> str:
        return urljoin(self.url, href.strip())

    @staticmethod
    def _pick_largest_from_srcset(srcset: str) -> str | None:
        # "url1 480w, url2 800w, url3 1200w" — take the biggest width
        candidates = []
        for part in srcset.split(","):
            bits = part.strip().split()
            if not bits:
                continue
            url = bits[0]
            width = 0
            if len(bits) > 1 and bits[1].endswith("w"):
                try:
                    width = int(bits[1][:-1])
                except ValueError:
                    pass
            candidates.append((width, url))
        if not candidates:
            return None
        candidates.sort(reverse=True)
        return candidates[0][1]

    @staticmethod
    def _is_real_image(url: str) -> bool:
        if url.startswith("data:"):
            return False  # inline base64 — usually 1x1 placeholders
        lowered = url.lower()
        # common tracking/spacer patterns
        junk = ("pixel.gif", "spacer.gif", "1x1.", "blank.gif", "transparent.png")
        return not any(j in lowered for j in junk)

    # ------------------------------------------------------------------
    # IMAGE DOWNLOADER
    # ------------------------------------------------------------------
    def download_images(self, urls: list[str], out_dir: str = "images",
                        delay_range: tuple[float, float] = (0.3, 1.0)) -> list[str]:
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        saved: list[str] = []
        headers = realistic_headers(self.user_agent)
        headers["Referer"] = self.url  # many CDNs require this

        for i, url in enumerate(urls):
            try:
                r = cffi_requests.get(
                    url, headers=headers, impersonate="chrome131", timeout=15
                )
                r.raise_for_status()
                ext = self._guess_extension(url, r.headers.get("Content-Type", ""))
                fname = f"{i:04d}_{self._safe_name(url)}{ext}"
                path = os.path.join(out_dir, fname)
                with open(path, "wb") as f:
                    f.write(r.content)
                saved.append(path)
                time.sleep(random.uniform(*delay_range))
            except Exception as e:
                print(f"[SKIP {url}] {e}")
        return saved

    @staticmethod
    def _guess_extension(url: str, content_type: str) -> str:
        path = urlparse(url).path
        ext = os.path.splitext(path)[1].lower()
        if ext in (".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".bmp", ".avif"):
            return ext
        guess = mimetypes.guess_extension((content_type or "").split(";")[0].strip())
        return guess or ".jpg"

    @staticmethod
    def _safe_name(url: str) -> str:
        name = os.path.basename(urlparse(url).path) or "image"
        name = os.path.splitext(name)[0]
        return "".join(c if c.isalnum() or c in "-_" else "_" for c in name)[:50]


# ----------------------------------------------------------------------
if __name__ == "__main__":
    target = input("URL: ").strip()
    s = StealthScraper(target)
    soup = s.scrape()
    if soup:
        imgs = s.extract_images(soup)
        print(f"\nFound {len(imgs)} images")
        for u in imgs[:20]:
            print(" -", u)

        if imgs and input("\nDownload? [y/N] ").lower().startswith("y"):
            saved = s.download_images(imgs)
            print(f"Saved {len(saved)} files to ./images/")
