import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# Regex patterns for common secrets
SECRET_PATTERNS =  {
    'google_api'     : r'AIza[0-9A-Za-z-_]{35}',
    'firebase'  : r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
    'google_captcha' : r'6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$',
    'google_oauth'   : r'ya29\.[0-9A-Za-z\-_]+',
    'amazon_aws_access_key_id' : r'A[SK]IA[0-9A-Z]{16}',
    'amazon_mws_auth_toke' : r'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    'amazon_aws_url' : r's3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com',
    'amazon_aws_url2' : r"(" \
           r"[a-zA-Z0-9-\.\_]+\.s3\.amazonaws\.com" \
           r"|s3://[a-zA-Z0-9-\.\_]+" \
           r"|s3-[a-zA-Z0-9-\.\_\/]+" \
           r"|s3.amazonaws.com/[a-zA-Z0-9-\.\_]+" \
           r"|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\.\_]+)",
    'facebook_access_token' : r'EAACEdEose0cBA[0-9A-Za-z]+',
    'authorization_basic' : r'basic [a-zA-Z0-9=:_\+\/-]{5,100}',
    'authorization_bearer' : r'bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}',
    'authorization_api' : r'api[key|_key|\s+]+[a-zA-Z0-9_\-]{5,100}',
    'mailgun_api_key' : r'key-[0-9a-zA-Z]{32}',
    'twilio_api_key' : r'SK[0-9a-fA-F]{32}',
    'twilio_account_sid' : r'AC[a-zA-Z0-9_\-]{32}',
    'twilio_app_sid' : r'AP[a-zA-Z0-9_\-]{32}',
    'paypal_braintree_access_token' : r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
    'square_oauth_secret' : r'sq0csp-[ 0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}',
    'square_access_token' : r'sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}',
    'stripe_standard_api' : r'sk_live_[0-9a-zA-Z]{24}',
    'stripe_restricted_api' : r'rk_live_[0-9a-zA-Z]{24}',
    'github_access_token' : r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*',
    'rsa_private_key' : r'-----BEGIN RSA PRIVATE KEY-----',
    'ssh_dsa_private_key' : r'-----BEGIN DSA PRIVATE KEY-----',
    'ssh_dc_private_key' : r'-----BEGIN EC PRIVATE KEY-----',
    'pgp_private_block' : r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
    'json_web_token' : r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$',
    'slack_token' : r"\"api_token\":\"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\"",
    'SSH_privKey' : r"([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)",
    'Heroku API KEY' : r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
    'possible_Creds' : r"(?i)(" \
                    r"password\s*[`=:\"]+\s*[^\s]+|" \
                    r"password is\s*[`=:\"]*\s*[^\s]+|" \
                    r"pwd\s*[`=:\"]*\s*[^\s]+|" \
                    r"passwd\s*[`=:\"]+\s*[^\s]+)",
}

def fetch_page(url):
    """Fetch the content of a webpage."""
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"Error fetching {url}: {e}")
        return None

def extract_js_files(html, base_url):
    """Extract all JavaScript (.js) file links from the HTML content."""
    soup = BeautifulSoup(html, 'html.parser')
    js_files = set()
    for script in soup.find_all('script', src=True):
        js_url = urljoin(base_url, script['src'])
        if js_url.endswith('.js'):  # Ensure the link is a JavaScript file
            js_files.add(js_url)
    return js_files

def find_secrets_in_js(js_url):
    """Find secrets in a JavaScript file."""
    js_content = fetch_page(js_url)
    if not js_content:
        return

    print(f"\nScanning: {js_url}")
    secrets_found = False
    for secret_type, pattern in SECRET_PATTERNS.items():
        matches = re.findall(pattern, js_content)
        if matches:
            secrets_found = True
            print(f"Found {secret_type}(s):")
            for match in matches:
                print(f"  - {match}")
    
    if not secrets_found:
        print("No secrets found in this file.")

def crawl_website_for_js_and_secrets(url, max_depth=2):
    """Crawl a website, find JavaScript files, and detect secrets."""
    visited = set()
    to_visit = [(url, 0)]  # (url, depth)

    while to_visit:
        current_url, depth = to_visit.pop(0)
        if current_url in visited or depth > max_depth:
            continue

        print(f"\nCrawling: {current_url} (Depth: {depth})")
        visited.add(current_url)

        html = fetch_page(current_url)
        if not html:
            continue

        # Find JavaScript files
        js_files = extract_js_files(html, current_url)
        print(f"Found {len(js_files)} JavaScript files:")
        for js_file in js_files:
            print(f"  - {js_file}")

        # Analyze JavaScript files for secrets
        for js_file in js_files:
            find_secrets_in_js(js_file)

        # Add new links to the queue
        for link in extract_links(html, current_url):
            if link not in visited:
                to_visit.append((link, depth + 1))

def extract_links(html, base_url):
    """Extract all links from the HTML content."""
    soup = BeautifulSoup(html, 'html.parser')
    links = set()
    for tag in soup.find_all(['a', 'link'], href=True):
        full_url = urljoin(base_url, tag['href'])
        links.add(full_url)
    return links

if __name__ == "__main__":
    target_url = input("Enter the target URL: ")
    crawl_website_for_js_and_secrets(target_url)
