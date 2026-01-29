import requests, logging, re, ssl, socket, certifi
from requests.exceptions import RetryError
from bs4 import Comment
from urllib.parse import urlparse, urljoin
from datetime import datetime

logger = logging.getLogger(__name__)

def_timeout = (4, 8)

#Base Response
def get_base_response(session, url):
    try:
        return safe_request(session, url, timeout=def_timeout)
    except RetryError as e:
        logger.warning(f"Base request failed: {e}")
        return None
    

#Handling response errors
def safe_request(session, url, **kwargs):
    try:
        return session.get(url, **kwargs)
    except requests.exceptions.ConnectTimeout:
        logger.warning(f"Timeout connecting to {url}")
    except requests.exceptions.ReadTimeout:
        logger.warning(f"Read timeout from {url}")
    except requests.exceptions.SSLError:
        logger.error(f"SSL error for {url}")
    except requests.exceptions.ConnectionError:
        logger.error(f"Connection error for {url}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Request failed: {e}")
    return None



#HTTP Security Checks
def http_security_scan(r, headers, session, parsed_url, base_url, add_finding):
    check_https(session, parsed_url, base_url, add_finding)
    check_security_headers(headers, add_finding)
    check_csp_header(headers, add_finding)
    check_status_code(r, add_finding)
    check_cookies(r, add_finding)
    check_cors(headers, add_finding)

#Attack Surface Discovery Checks
def discovery_scan(base_url, session, links, add_finding):
    get_robots_txt(base_url, session, add_finding)
    find_exposed_endpoints(links, add_finding)
    find_exposed_dicts(base_url, session, add_finding)


#Client-side Checks
def client_side_scan(soup, add_finding):
    find_inline_js(soup, add_finding)
    find_third_party(soup, add_finding)
    find_mixed_content(soup, add_finding)


#Checking for HTTP to HTTPS redirection
def check_https(session, parsed_url, base_url, add_finding):
    https_url = parsed_url._replace(scheme="https").geturl()
    http_resp = safe_request(session, https_url, timeout=def_timeout, allow_redirects=False)

    if not http_resp:
        logger.info("Failed connection. Could not complete HTTPS check")
        add_finding(
            "http_security",
            "Missing HTTP to HTTPS redirect",
            "info",
            status="inconclusive",
            reason="failed connection"
        )
        return

    if not http_resp.is_redirect:
        logger.warning("No HTTP → HTTPS redirect")
        add_finding(
            "http_security",
            "Missing HTTP to HTTPS redirect",
            "medium",
            evidence={"url": str(base_url)},
            impact="Increased risk of data interception",
            recommendation="Include an HTTPS redirect"
        )


#Checking Headers
def check_security_headers(headers, add_finding):
    if not headers:
        logger.info("Unable to check for security headers")
        add_finding(
            "http_security",
            "Missing security header(s)",
            "info",
            status="inconclusive",
            reason="failed connection"
        )
        return

    security_headers = {
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
    }

    critical_headers = {
        "Content-Security-Policy",
        "Strict-Transport-Security"
    }

    found = []
    missing = []

    for h in security_headers:
        if h in headers:
            found.append(h)
        else:
            missing.append(h)
    
    if found:
        logger.info(f"Headers present: {found}")

    missing_critical = set(missing) & critical_headers

    if missing:
        logger.warning(f"Missing headers: {missing}")
        add_finding(
            "http_security",
            "Missing security header(s)",
            "medium" if missing_critical else "low",
            check_type="definitive",
            evidence={"Missing headers": missing},
            impact="Increased vulnerability to XSS, Clickjacking and MitM attacks",
            recommendation="Add missing header(s)"
        )


#CSP quality assessment
def check_csp_header(headers, add_finding):
    if not headers:
        logger.info("Unable to check for CSP header due to lack of access to headers")
        add_finding(
            "http_security",
            "Weak CSP directive",
            "info",
            status="inconclusive",
            reason="failed connection"
        )
        return

    csp = headers.get("Content-Security-Policy", "")
    if "unsafe-inline" in csp or "unsafe-eval" in csp:
        logger.warning("Weak CSP directive found")
        add_finding(
            "http_security",
            "Weak CSP directive",
            "medium",
            evidence={"csp": csp},
            impact="Increased risk of XSS and data injection attacks",
            recommendation="Avoid unsafe-inline and unsafe-eval directives"
        )

           

#Cross-Origin Resource Sharing
def check_cors(headers, add_finding):
    if not headers:
        logger.info("Unable to check for CORS header due to lack of access to headers")
        add_finding(
            "http_security",
            "Overly permissive CORS policy",
            "info",
            status="inconclusive",
            reason="failed connection"
        )
        return

    cors = headers.get("Access-Control-Allow-Origin")
    if cors and cors == "*":
        logger.warning("CORS allows any origin — potential risk")
        add_finding(
            "http_security",
            "Overly permissive CORS policy",
            "medium",
            evidence={"header": cors},
            impact="Increased risk of CSRF attacks and data exposure",
            recommendation="Avoid wildcard CORS origins"            
        )


#Checking status codes
def check_status_code(r, add_finding):
    if not r:
        logger.info("Unable to check status codes due to lack of a response")
        add_finding(
            "http_security",
            "Server error response",
            "info",
            status="inconclusive",
            reason="failed connection"
        )
        return
    
    stat = r.status_code

    if stat >= 500:
        logger.warning(f"Server Error: {stat}")
        add_finding(
            "http_security",
            "Server error response",
            "low",
            check_type="definitive",
            evidence={"status_code": stat},
            impact="Server errors may indicate instability",
            recommendation="Investigate server-side logs"
        )
    else:
        logger.info(f"Status code: {stat}")


#Cookies
def check_cookies(r, add_finding):
    if not r:
        logger.info("Unable to check cookies due to lack of a response")
        add_finding(
            "http_security",
            "Insecure cookie attributes",
            "info",
            status="inconclusive",
            reason="failed connection"
        )
        return
    
    if not r.cookies:
        logger.info("No cookies were set by the application")
        return

    issues = {}
    no_secure = []
    no_http = []
    no_samesite = []

    cookies = r.cookies
    for cookie in cookies:
        attrs = {k.lower() for k in cookie._rest.keys()}  
        if "secure" not in attrs:
            no_secure.append(cookie.name)

        if "httponly" not in attrs:
            no_http.append(cookie.name)

        if "samesite" not in attrs:
            no_samesite.append(cookie.name)
        
    if no_secure:
        logger.warning(f"Cookie(s) missing Secure flag: {no_secure}")
        issues["missing_secure"] = no_secure
    
    if no_http:
        logger.warning(f"Cookie(s) missing HttpOnly flag: {no_http}")
        issues["missing_httponly"] = no_http
        
    if no_samesite:
        logger.warning(f"Cookie(s) missing SameSite attribute: {no_samesite}")
        issues["missing_samesite"] = no_samesite
        
    if issues:
        add_finding(
                "http_security",
                "Insecure cookie attributes",
                "medium",
                evidence={"affected cookie(s)": issues},
                impact="Increased vulnerability to XSS and CSRF attacks",
                recommendation="Set Secure, HttpOnly, and appropriate SameSite attributes on cookies"              
            )

#Robots
def get_robots_txt(base_url, session, add_finding):
    base = urlparse(base_url)
    robots = f"{base.scheme}://{base.netloc}/robots.txt"
    resp = safe_request(session, robots, timeout=def_timeout)
  
    if not resp:
        logger.info(f"Robots file request error")
        add_finding(
            "discovery",
            "robots.txt missing",
            "info",
            status="inconclusive",
            reason="failed connection"
        )
        return

    if resp.status_code == 200:
        logger.info("robots.txt found")
        for line in resp.text.splitlines():
            if line.lower().startswith("sitemap:"):
                logger.info(f"Sitemap found: {line.split(':')[1].strip()}")
    else:
        logger.warning("robots.txt missing or inaccessible")
        add_finding(
            "discovery",
            "robots.txt missing",
            "low",
            check_type="definitive",
            impact="Increased server load and inefficient crawling",
            recommendation="Add a robots.txt file"
        )


#Common Files Exposure
def find_exposed_dicts(base_url, session, add_finding):
    common = [".git/", "backup.zip", "env", "config.php"]
    incomplete_requests = []
    found = []

    for path in common:
        url = urljoin(base_url, path)
        resp = safe_request(session, url, timeout=def_timeout)

        if not resp:
            incomplete_requests.append(path)
            continue

        
        if resp.status_code == 200:
            found.append(path)

    if found:
        logger.warning(f"Exposed file(s): {found}")
        add_finding(
                "discovery",
                "Sensitive file(s) exposed",
                "high",
                evidence={"file(s)": found},
                impact="Unauthourized access to important data",
                recommendation="Restrict access to sensitive files"
            )
        
    if incomplete_requests:
        logger.info(f"Exposed dicts request error for {incomplete_requests}")
        add_finding(
            "discovery",
            "Sensitive file(s) exposed",
            "info",
            status="inconclusive",
            reason=f"failed connection to the following path(s): {incomplete_requests}"
        )



#Detecting Exposed Metadata 
def find_exposed_metadata(soup, add_finding):
    if not soup:
        logger.info("Unable to check for exposed metadata due to lack of a response")
        add_finding("info_leak",
                    "Technology disclosure",
                    "info",
                    status="inconclusive",
                    reason="failed connection"
                    )
        return
    
    RISKY_META_NAMES = {
        "generator",
        "application-name",
        "environment",
        "build",
        "version",
        "framework",
        "server",
    }
    RISKY_HTTP_EQUIV = {"x-ua-compatible", "content-security-policy"}

    meta_tags = soup.find_all("meta")

    issues = {}
    found_meta = {}
    found_http = {}

    for meta in meta_tags:
        name = meta.get("name", "").lower()
        http_equiv = meta.get("http-equiv", "").lower()
        content = meta.get("content", "")

        if name in RISKY_META_NAMES:
            found_meta[name] = content

        if http_equiv in RISKY_HTTP_EQUIV:
            found_http[http_equiv] = content
    
    if found_meta:
        logger.warning(f"Exposed metadata found: {found_meta}")
        issues["meta_tags"] = found_meta

    if found_http:
        logger.warning(f"Meta http-equiv disclosure: {found_http}")
        issues["http_equiv_tags"] = found_http

    if issues: 
        add_finding(
                "info_leak",
                "Technology disclosure",
                "low",
                evidence={"found_tags": issues},
                impact="Information leakage and privacy violations",
                recommendation="Remove this information from the website HTML"
            )
    

#Identifying Risky Comments
def find_comments(soup, add_finding):
    if not soup:
        logger.info("Unable to check for comments due to lack of a response")
        add_finding("info_leak",
                    "Comments",
                    "info",
                    status="inconclusive",
                    reason="failed connection"
                    )
        return
    
    found = []
    comments = soup.find_all(string=lambda text: isinstance(text, Comment))
    for c in comments:
        found.append(c)
    
    if found:
        logger.warning(f"Comment(s) found: {found}")
        add_finding(
            "info_leak",
            "Comments",
            "medium",
            evidence={"comment(s)": found},
            impact="Data exposure",
            recommendation="Remove comments from the website code"
        )


#Finding Insecure Forms (critical)
def find_insecure_forms(soup, add_finding):
    if not soup:
        logger.info("Unable to check for insecure forms due to lack of a response")
        add_finding("inputs",
                    "Insecure forms",
                    "info",
                    status="inconclusive",
                    reason="failed connection"
                    )
        return
    
    found = []
    forms = soup.find_all("form")
    for form in forms:
        inputs = form.find_all("input")
        for input in inputs:
            if input.get("name") and "csrf" not in input.get("name").lower():
                found.append(form.name)
            
    if found:
        logger.warning("No obvious CSRF token name")
        add_finding(
            "inputs",
            "Insecure forms",
            "medium",
            evidence={"form(s) found": found},
            impact="Vulnerability to data manipulation and session hijacking",
            recommendation="Add a CSRF token"
        )


#Detect mixed content (HTTPS broken security)
def find_mixed_content(soup, add_finding):
    if not soup:
        logger.info("Unable to check for mixed content due to lack of a response")
        add_finding("client_side",
                    "Mixed content",
                    "info",
                    status="inconclusive",
                    reason="failed connection"
                    )
        return
    
    found = []
    for tag in soup.find_all(["script", "img", "link"]):
        src = tag.get("src") or tag.get("href")
        if src and src.startswith("http://"):
            found.append(src)
    
    if found:
        logger.warning(f"Mixed content: {found}")
        add_finding(
            "client_side",
            "Mixed content",
            "medium",
            evidence={"content": found},
            impact="Increased vulnerability to data interception",
            recommendation="Load all page sources over HTTPS"
        )


#Checking for endpoint exposure
def find_exposed_endpoints(links, add_finding):
    if not links:
        logger.info("Unable to check for endpoint exposure due to lack of a response")
        add_finding("discovery",
                    "Sensitive endpoint discovered",
                    "info",
                    status="inconclusive",
                    reason="failed connection"
                    )
        return
    
    found = []
    patterns = re.compile(r"/admin|/login|/api", re.IGNORECASE)
    for link in links:
        href = link.get("href")
        if href and patterns.search(href):
            found.append(href)
    
    if found:
        logger.warning(f"⚠️ Exposed endpoint(s) found: {found}")
        add_finding(
            "discovery",
            "Sensitive endpoint discovered",
            "medium",
            evidence={"path(s)": found},
            impact="Unwanted access to sensitive endpoints",
            recommendation="Use authentication and authorization"
        )


#Detection Open Redirects
def find_suspicious_redirects(links, add_finding):
    if not links:
        logger.info("Unable to check for open redirects due to lack of a response")
        add_finding("redirects",
                    "Open redirects",
                    "info",
                    status="inconclusive",
                    reason="failed connection"
                    )
        return
    
    found = []
    patterns = re.compile(r"redirect|url|next|return|dest|destination", re.IGNORECASE)
    for link in links:
        href = link.get("href")
        if href and patterns.search(href):
            found.append(href)

    if found:
        logger.warning(f"⚠️ Potential open redirect(s) found: {found}")
        add_finding(
            "redirects",
            "Open redirects",
            "medium",
            evidence={"redirects": found},
            impact="Vulnerability to advanced phishing attacks",
            recommendation="Validate redirect URIs against a pre-registered whitelist"
        )



#Identifying Third-party Integrations
def find_third_party(soup, add_finding):
    if not soup:
        logger.info("Unable to check for third party integrations due to lack of a response")
        add_finding("client_side",
                    "Third party integration",
                    "info",
                    status="inconclusive",
                    reason="failed connection"
                    )
        return
    
    found = []
    patterns = re.compile(
        r"google-analytics.com|googletagmanager.com|facebook.net|stripe.com|cloudflare.com|hotjar.com|cdn.jsdelivr.net",
        re.IGNORECASE
    )

    for tag in soup.find_all(["script", "link"], src=True):
        src = tag.get("src")
        if patterns.search(src):
            found.append(src)


    if found:
        logger.warning(f"⚠️ Potential third party integration(s) detected: {found}")
        add_finding(
            "client_side",
            "Third party integration",
            "low",
            evidence={"integration(s)": found},
            impact="Increases the attack surface",
            recommendation="Use strict permissions and limit the data accessible to third parties"
        )


#Detecting Inline JavaScript
def find_inline_js(soup, add_finding):
    if not soup:
        logger.info("Unable to check for inline JavaScript due to lack of a response")
        add_finding("client_side",
                    "Inline JavaScript",
                    "info",
                    status="inconclusive",
                    reason="failed connection"
                    )
        return
    
    found = []
    scripts = soup.find_all("script")
    for s in scripts:
        if s.string:
            found.append(str(s))
    

    if found:
        logger.warning(f"Inline JS detected: {found}")
        add_finding(
                "client_side",
                "Inline JavaScript",
                "low",
                evidence={"content": found},
                recommendation="Use a separate, external file for JavaScript"
            )


#Checking SSL Certificates
def get_ssl_certificate(hostname, add_finding): 
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT) 
    context.load_verify_locations(cafile=certifi.where()) 
    context.check_hostname = True 
    context.verify_mode = ssl.CERT_REQUIRED 

    try: 
        with socket.create_connection((hostname, 443)) as sock: 
            with context.wrap_socket(sock, server_hostname=hostname) as ssock: 
                cert = ssock.getpeercert() 
                if not cert: 
                    logger.info(f"No certificate retrieved for {hostname}")
                    add_finding("ssl",
                    "SSL certificate status",
                    "info",
                    status="inconclusive",
                    reason="failed connection"
                    )
                    return 
                else: 
                    return cert
    except Exception as e: 
        logger.info(f"Error retrieving SSL certificate: {e}")
        add_finding("ssl",
                    "SSL certificate status",
                    "info",
                    status="inconclusive",
                    reason="failed connection"
                    )


def check_ssl_certificate(now, hostname, cert, add_finding):
    try:
        not_after_str = cert["notAfter"]
        not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
    except (KeyError, ValueError) as e:
        if isinstance(e, KeyError):
            logger.error("Certificate missing 'notAfter' field")
        else:
            logger.error("Could not parse certificate expiration date")

        add_finding(
            "ssl",
            "SSL certificate status",
            "info",
            status="inconclusive",
            reason="failed connection"
        )
        return


    days_left = not_after - now

    if not_after > now:
        logger.info(f"SSL certificate for {hostname} is valid until {not_after}.")
        add_finding(
                "ssl",
                "SSL certificate status",
                "info",
                evidence={"expires_on": not_after.isoformat()},
                result="expired",
                impact="If the SSL certificate expires, user data will be exposed to theft",
                recommendation="Start thinking about renewal"
            )
        if days_left.days <= 30:
            logger.warning(f"Number of days remaining until expiration: {days_left.days}.")
            add_finding(
                "ssl",
                "SSL certificate status",
                "low",
                evidence={"expires_on": not_after.isoformat()},
                result="expiring_soon",
                impact="If the SSL certificate expires, user data will be exposed to theft",
                recommendation="Renew SSL certificate"
            )
    else:
        logger.warning(f"SSL certificate for {hostname} has expired on {not_after}.")
        add_finding(
            "ssl",
            "SSL certificate status",
            "high",
            evidence={"expires_on": not_after.isoformat()},
            result="valid_long",
            impact="Exposes user data to theft",
            recommendation="Renew SSL certificate immediately"
        )

