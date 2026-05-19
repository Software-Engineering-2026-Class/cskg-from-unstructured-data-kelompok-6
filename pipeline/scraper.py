import feedparser
from bs4 import BeautifulSoup
import redis
import json
import time
import requests


# --- Configuration ---
RSS_FEEDS = {
    "TheHackerNews": "http://feeds.feedburner.com/TheHackersNews",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "KrebsOnSecurity": "https://krebsonsecurity.com/feed/",
    "FortiGuardLabs": "https://filestore.fortinet.com/fortiguard/rss/outbreakalert.xml",
}
MAX_ARTICLES_PER_FEED = 2

# Redis connection details
# We use 'redis' as the host name because it's the service name in docker-compose
R_HOST = "redis"
R_PORT = 6379
ARTICLES_QUEUE = "articles_queue"  # List to push new articles to
SEEN_URLS_SET = "seen_urls"  # Set to track duplicates


def clean_html(html_content):
    """Strips all HTML tags from a string."""
    soup = BeautifulSoup(html_content, "html.parser")
    return soup.get_text()


def fetch_articles(feed_url, max_articles=5):
    """Fetches and cleans articles from an RSS feed."""
    print(f"Fetching articles from: {feed_url}")
    feed = feedparser.parse(feed_url)
    articles = []

    for entry in feed.entries[:max_articles]:
        articles.append(
            {
                "title": entry.title,
                "link": entry.link,
                "published": entry.get("published", "N/A"),
                "content": clean_html(entry.get("summary", "")),
            }
        )
    return articles

def fetch_nvd_articles(max_articles=5):
    """Fetches recent CVE descriptions from the NVD API."""
    print("Fetching articles from: NVD CVE API")
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=10"
    try:
        response = requests.get(url, timeout=10)
        data = response.json()
        articles = []
        for vuln in data.get("vulnerabilities", [])[:max_articles]:
            cve = vuln["cve"]
            cve_id = cve["id"]
            description = cve.get("descriptions", [{}])[0].get("value", "No description.")
            articles.append({
                "title": cve_id,
                "link": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "published": cve.get("published", "N/A"),
                "content": description,
            })
        return articles
    except Exception as e:
        print(f"NVD fetch failed: {e}")
        return []


def fetch_malwarebazaar(max_articles=5):
    """Fetches recent malware reports from MalwareBazaar."""
    print("Fetching articles from: MalwareBazaar API")
    url = "https://mb-api.abuse.ch/api/v1/"
    try:
        response = requests.post(url, data={"query": "get_recent", "selector": "100"}, timeout=10)
        data = response.json()
        articles = []
        for sample in data.get("data", [])[:max_articles]:
            malware_name = sample.get("signature") or sample.get("tags", ["unknown"])[0]
            sha256 = sample.get("sha256_hash", "")
            content = (
                f"Malware: {malware_name}. "
                f"File type: {sample.get('file_type', 'N/A')}. "
                f"Tags: {', '.join(sample.get('tags') or [])}. "
                f"Reporter: {sample.get('reporter', 'N/A')}."
            )
            articles.append({
                "title": f"MalwareBazaar: {malware_name} ({sha256[:16]}...)",
                "link": f"https://bazaar.abuse.ch/sample/{sha256}",
                "published": sample.get("first_seen", "N/A"),
                "content": content,
            })
        return articles
    except Exception as e:
        print(f"MalwareBazaar fetch failed: {e}")
        return []


def connect_to_redis():
    """Connects to Redis with retries."""
    while True:
        try:
            r = redis.Redis(host=R_HOST, port=R_PORT, decode_responses=True)
            r.ping()
            print("Producer connected to Redis.")
            return r
        except redis.ConnectionError as e:
            print(f"Producer waiting for Redis... ({e})")
            time.sleep(5)


def run_producer():
    r = connect_to_redis()

    all_articles = []
    for _, url in RSS_FEEDS.items():
        all_articles.extend(fetch_articles(url, MAX_ARTICLES_PER_FEED))
    all_articles.extend(fetch_nvd_articles(MAX_ARTICLES_PER_FEED))
    all_articles.extend(fetch_malwarebazaar(MAX_ARTICLES_PER_FEED))

    new_articles_pushed = 0
    for article in all_articles:
        # Check if this URL is already in our 'seen' set
        if not r.sismember(SEEN_URLS_SET, article["link"]):
            # If not, add it to the queue and the set
            article_json = json.dumps(article)
            r.rpush(ARTICLES_QUEUE, article_json)
            r.sadd(SEEN_URLS_SET, article["link"])

            new_articles_pushed += 1
            print(f"  [PRODUCER] Found new article: {article['title']}")

    print(
        f"Producer run complete. Pushed {new_articles_pushed} new articles to '{ARTICLES_QUEUE}'."
    )


if __name__ == "__main__":
    run_producer()
