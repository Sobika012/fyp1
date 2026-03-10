import requests #type: ignore
from urllib.parse import urljoin, urlparse, urlencode
from bs4 import BeautifulSoup #type: ignore

DEFAULT_TIMEOUT = 10
MAX_INTERNAL_PAGES = 10  # depth-1 limit


def is_same_domain(base_url, target_url):
    return urlparse(base_url).netloc == urlparse(target_url).netloc


def normalize_url(url):
    parsed = urlparse(url)
    path = parsed.path or "/"
    if path != "/" and path.endswith("/"):
        path = path[:-1]
    final = f"{parsed.scheme}://{parsed.netloc}{path}"
    if parsed.query:
        final += f"?{parsed.query}"
    return final


def extract_links(base_url, html):
    soup = BeautifulSoup(html, "html.parser")
    links = set()

    for tag in soup.find_all("a", href=True):
        href = tag.get("href")
        full_url = urljoin(base_url, href)

        # Only HTTP/S
        if full_url.startswith("http"):
            links.add(normalize_url(full_url))

    return links


def build_form_data(form_tag):
    fields = {}
    for tag in form_tag.find_all(["input", "select", "textarea"]):
        name = tag.get("name")
        if not name:
            continue

        if tag.has_attr("disabled"):
            continue

        tag_type = (tag.get("type") or "").lower()
        if tag_type in ["submit", "button", "reset", "file", "image"]:
            continue

        # Keep deterministic placeholder values for sqlmap.
        fields[name] = "1"

    return fields


def extract_forms(base_url, html, target_url):
    soup = BeautifulSoup(html, "html.parser")
    targets = []

    for form in soup.find_all("form"):
        action = form.get("action") or base_url
        method = (form.get("method") or "get").upper()
        enctype = (form.get("enctype") or "").lower()

        form_url = normalize_url(urljoin(base_url, action))

        if not form_url.startswith("http"):
            continue

        if not is_same_domain(target_url, form_url):
            continue

        fields = build_form_data(form)
        if not fields:
            continue

        is_json = "application/json" in enctype

        if method == "GET":
            query = urlencode(fields, doseq=False)
            if "?" in form_url:
                full_url = f"{form_url}&{query}"
            else:
                full_url = f"{form_url}?{query}"

            targets.append({
                "type": "form-get",
                "url": normalize_url(full_url),
                "method": "GET"
            })
        else:
            if is_json:
                import json
                payload = json.dumps(fields)
            else:
                payload = urlencode(fields, doseq=False)

            targets.append({
                "type": "form-post-json" if is_json else "form-post",
                "url": form_url,
                "method": "POST",
                "data": payload,
                "is_json": is_json
            })

    return targets


def crawl_sqlmap_targets(target_url, request_headers=None, request_cookies=None):
    """
    Lightweight depth-1 crawler for SQLMap targets:
    - Crawls homepage
    - Visits up to 10 internal pages
    - Extracts parameterized URLs
    - Extracts GET/POST form targets
    """

    print(f"[*] Crawling {target_url} for SQLMap-ready targets...")

    visited = set()
    parameterized_urls = set()
    form_targets = []
    internal_links = set()

    req_kwargs = {
        "timeout": DEFAULT_TIMEOUT,
        "verify": False
    }

    if request_headers:
        req_kwargs["headers"] = request_headers
    if request_cookies:
        req_kwargs["cookies"] = request_cookies

    try:
        response = requests.get(target_url, **req_kwargs)
        if response.status_code != 200:
            return []

        homepage_links = extract_links(target_url, response.text)
        homepage_forms = extract_forms(target_url, response.text, target_url)
        form_targets.extend(homepage_forms)

        for link in homepage_links:
            if is_same_domain(target_url, link):
                internal_links.add(link)

    except Exception:
        return []

    # Limit internal pages to prevent overload
    internal_links = list(internal_links)[:MAX_INTERNAL_PAGES]

    # Visit each internal page
    for link in internal_links:
        if link in visited:
            continue

        visited.add(link)

        try:
            r = requests.get(link, **req_kwargs)
            if r.status_code != 200:
                continue

            page_links = extract_links(link, r.text)
            page_forms = extract_forms(link, r.text, target_url)

            for pl in page_links:
                if "?" in pl and is_same_domain(target_url, pl):
                    parameterized_urls.add(normalize_url(pl))

            form_targets.extend(page_forms)

        except Exception:
            continue

    targets = []
    for u in parameterized_urls:
        targets.append({
            "type": "get",
            "url": normalize_url(u),
            "method": "GET"
        })
    targets.extend(form_targets)

    print(f"[+] Crawler found {len(targets)} SQLMap-ready targets.")
    return targets


def crawl(target_url):
    """
    Lightweight depth-1 crawler:
    - Crawls homepage
    - Visits up to 10 internal pages
    - Extracts parameterized URLs
    """

    sqlmap_targets = crawl_sqlmap_targets(target_url)
    urls = []
    for t in sqlmap_targets:
        if t.get("method") == "GET" and "?" in t.get("url", ""):
            urls.append(t["url"])
    return urls
