import requests, json, logging, argparse, uuid, sys
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from datetime import datetime
from render import render_report, write_markdown_report, json_report
from checks import get_base_response, http_security_scan, get_ssl_certificate, check_ssl_certificate, discovery_scan, client_side_scan, find_insecure_forms, find_suspicious_redirects, find_exposed_metadata, find_comments


#ARGPARSE
parser = argparse.ArgumentParser(description="Automated Web Security Audit Tool")
parser.add_argument("base_url", help="Target url for the audit")
parser.add_argument("--http_security", action="store_true", help="Checks how securely the server responds to requests.")
parser.add_argument("--ssl", action="store_true", help="Check TLS/SSL security")
parser.add_argument("--discovery", action="store_true", help="Discovering the attack surface")
parser.add_argument("--client_side", action="store_true", help="Check client_side security")
parser.add_argument("--inputs", action="store_true", help="Checks if sensitive user data is being handled securely")
parser.add_argument("--info_leak", action="store_true", help="Checks if information that could help attackers is being leaked")
parser.add_argument("--redirects", action="store_true", help="Checks for redirects")
parser.add_argument("--full_scan", action="store_true", help="Run all available security checks")
parser.add_argument("--json", action="store_true", help="Produce JSON summary")
parser.add_argument("--document", action="store_true", help="Produce JSON summary and markdown report")
args = parser.parse_args()


#LOGGING
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
console = logging.StreamHandler()
file_handler = logging.FileHandler("scanner.log", mode="a", encoding="utf-8")
logger.addHandler(console)
logger.addHandler(file_handler)
formatter = logging.Formatter(
    "%(asctime)s - %(levelname)s - %(message)s",
    style="%",
    datefmt="%Y-%m-%d %H:%M"
)
console.setFormatter(formatter)
file_handler.setFormatter(formatter)


partial_failure = False
seen_findings = set()

EXIT_OK = 0
EXIT_INVALID_INPUT = 1
EXIT_PARTIAL_FAILURE = 2


#MAIN
def main(base_url):
    now = datetime.now()
    right_now = now.strftime("%d-%m-%Y %H:%M:%S")
    base_url = args.base_url
    parsed_url = urlparse(base_url)
    hostname = parsed_url.netloc
    required = parsed_url.scheme

    filename = f"audit_{hostname}_{right_now}.md"

    audit_results, add_finding = finding_collector()

    audit_results["target"] = base_url
    audit_results["scan_time"] = right_now

    invalid_input = False

    #Validating target url
    if not hostname or not required:
        invalid_input = True
        return

    #Session Handling
    retry_strategy = Retry(
    total=3,
    status_forcelist=[403, 429, 500, 502, 503, 504]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)

    with requests.Session() as session:
        session.headers.update({
            "User-Agent": "BasicWebSecurityAudit/1.0"
        })
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        r = get_base_response(session, base_url)


    headers = dict(r.headers) if r else {}

    soup = BeautifulSoup(r.text, "html.parser") if r else None
    links = soup.find_all("a", href=True) if soup else []

    if args.http_security or args.full_scan:
        http_security_scan(r, headers, session, parsed_url, base_url, add_finding)
    
    if args.ssl or args.full_scan:
        cert = get_ssl_certificate(hostname, add_finding)
        if cert:
            check_ssl_certificate(now,hostname, cert, add_finding)

    if args.discovery or args.full_scan:
        discovery_scan(base_url, session, links, add_finding)

    if args.client_side or args.full_scan:
        client_side_scan(soup, add_finding)

    if args.inputs or args.full_scan:
        find_insecure_forms(soup, add_finding)

    if args.info_leak or args.full_scan:
        find_exposed_metadata(soup, add_finding)
        find_comments(soup, add_finding)

    if args.redirects or args.full_scan:
        find_suspicious_redirects(links, add_finding)

    sort_findings(audit_results)

    if args.document or args.json:
        json_report(audit_results)
    
    if args.document:
        md = render_report(base_url, right_now)
        write_markdown_report(md, filename)

    #Exit Logic
    if invalid_input:
        return EXIT_INVALID_INPUT
    if partial_failure:
        return EXIT_PARTIAL_FAILURE
    return EXIT_OK


#Updating results
def finding_collector():
    audit_results = {
    "target": None,
    "scan_time": None,
    "findings": {
    "http_security": [],
    "ssl": [],
    "discovery": [],
    "client_side": [],
    "inputs": [],
    "info_leak": [],
    "redirects": []
    }
    }

    def add_finding(
        category,
        issue,
        severity,
        *,
        status="found",
        reason=None,
        confidence=None,
        check_type=None,
        evidence=None,
        result=None,
        impact=None,
        recommendation=None
    ):
        global partial_failure

        #Classification defaults
        if check_type is None:
            check_type = "definitive" if severity in {"high", "medium"} else "heuristic"

        if confidence is None:
            if check_type == "definitive":
                confidence = "high" 
            elif status == "inconclusive":
                confidence = "low"
            else:
                confidence = "medium"

        finding = {
            "id": str(uuid.uuid4()), 
            "category": category,
            "issue": issue,
            "severity": severity,
            "status": status,
            "confidence": confidence,
            "check_type": check_type,
        }

        if evidence:
            finding["evidence"] = evidence
        if impact:
            finding["impact"] = impact
        if recommendation:
            finding["recommendation"] = recommendation
        if reason:
            finding["reason"] = reason
        if result:
            finding["result"] = result

        if status == "inconclusive":
            partial_failure = True

        f = fingerprint(finding)
        if f in seen_findings:
            return
        
        seen_findings.add(f)
        audit_results["findings"][category].append(finding)
    
    return audit_results, add_finding


#Deduplication
def fingerprint(f):
    return (
        f["category"],
        f["issue"],
        f.get("status"),
        json.dumps(f.get("evidence", "reason"), sort_keys=True)
    )


def sort_findings(audit_results):
    SEVERITY_ORDER = {
        "high": 0,
        "medium": 1,
        "low": 2,
        "info": 3
    }

    for category in audit_results["findings"]:
        audit_results["findings"][category].sort(
            key=lambda f: (
                SEVERITY_ORDER.get(f["severity"], 99),
                f["category"],
                f["issue"]
            )
        )


if __name__ == "__main__":
    sys.exit(main(args.base_url))
