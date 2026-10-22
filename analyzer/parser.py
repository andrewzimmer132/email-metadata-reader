import ipaddress
from email import policy
from email.parser import Parser
from email.utils import parseaddr
import re
from urllib.parse import urlsplit


def analyze_header(raw_header):

    email = Parser(policy=policy.default).parsestr(raw_header)

    results = {
        "from": email.get("From"),
        "to": email.get("To"),
        "subject": email.get("Subject"),
        "date": email.get("Date"),
        "return_path": email.get("Return-Path"),
        "message_id": email.get("Message-ID"),
        #received gets the list of servers the email passed through
        "received": get_received(email),
        #authentication of the received path
        "authentication": get_authentication(email)
    }

    return results

def analyze_body(raw_body):
    regex = (
        r"""(?i)\b(?:"""
        r"""(?:https?://|www\.)[^\s<>"']+"""
        r"""|(?:[a-z0-9-]+\.)+"""
        r"""(?:com|net|org|edu|gov|io|co|info|biz|me|us|uk|ca|au)"""
        r"""(?:/[^\s<>"']*)?"""
        r""")"""
    )
    body_results = []
    urls = re.findall(regex, raw_body)
    for url in urls:
        parsed = urlsplit(url if "://" in url else "//")
        hostname = parsed.hostname
        warnings = get_url_warnings(url, hostname)
        body_results.append({
            "match": url,
            "host": hostname,
            "warnings": warnings,
        })
    print(body_results)
    return body_results

def assess_spam(header_results, body, body_results, spoof_flags=None):

    header_results = header_results or {}
    body = body or ""
    body_results = body_results or []
    spoof_flags = spoof_flags or []

    score = 0
    warnings = []

    def add_warning(points, message):
        nonlocal score
        score += points
        warnings.append(message)

    from_value = header_results.get("from") or ""
    return_path = header_results.get("return_path") or ""
    subject = header_results.get("subject") or ""
    authentication = header_results.get("authentication") or ""

    from_address = parseaddr(from_value)[1].lower()
    return_path_address = parseaddr(return_path)[1].lower()

    authentication_text = (
        authentication
        if isinstance(authentication, str)
        else " ".join(authentication)
    ).lower()

    for mechanism in ("spf", "dkim", "dmarc"):
        if re.search(rf"\b{mechanism}\s*=\s*fail\b", authentication_text):
            add_warning(
                3,
                f"{mechanism.upper()} authentication failed."
            )

    if re.search(r"\b(spf|dkim|dmarc)\s*=\s*(softfail|neutral|none)\b",
                 authentication_text):
        add_warning(
            1,
            "One or more email authentication checks did not fully pass."
        )

    from_domain = from_address.rsplit("@", 1)[-1] if "@" in from_address else ""
    return_path_domain = (
        return_path_address.rsplit("@", 1)[-1]
        if "@" in return_path_address
        else ""
    )

    if from_domain and return_path_domain and from_domain != return_path_domain:
        add_warning(
            2,
            "The return path does NOT match where the user's domain is actually from."
        )

    if spoof_flags:
        add_warning(
            2,
            "There's unusual characters that the sender may be using to impersonate."
        )

    # Suspicious subject language.
    subject_patterns = (
        r"\b(act now|urgent|immediate action|required action)\b",
        r"\b(verify|confirm|suspend|locked|password reset)\b",
        r"\b(you have won|winner|claim your prize)\b",
    )

    if any(re.search(pattern, subject, re.IGNORECASE)
           for pattern in subject_patterns):
        add_warning(
            1,
            "Urgency/verification in this email may be subject to potential spam"
        )

    # Suspicious body language.
    body_patterns = (
        r"\b(click here|click the link|verify your account)\b",
        r"\b(send money|wire transfer|gift card| cryptocurrency)\b",
        r"\b(password|social security|credit card|bank account)\b",
    )

    if any(re.search(pattern, body, re.IGNORECASE)
           for pattern in body_patterns):
        add_warning(
            2,
            "The body requests a sensitive action or uses common phishing "
            "language."
        )

    if len(body_results) >= 3:
        add_warning(
            1,
            "The body contains multiple links."
        )

    # Links containing an IP address instead of a normal hostname.
    ip_url_pattern = (
        r"(?:https?://)?"
        r"(?:\d{1,3}\.){3}\d{1,3}"
    )

    if re.search(ip_url_pattern, body, re.IGNORECASE):
        add_warning(
            2,
            "The body contains a link that uses a raw IP address."
        )

    # URL shorteners hide the final destination.
    shortener_pattern = (
        r"\b(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|"
        r"is\.gd|buff\.ly)\b"
    )

    if re.search(shortener_pattern, body, re.IGNORECASE):
        add_warning(
            1,
            "The body contains a URL-shortening service that hides the "
            "destination."
        )

    if score >= 5:
        level = "high"
    elif score >= 2:
        level = "medium"
    else:
        level = "low"

    return {
        "potential_spam": score >= 2,
        "level": level,
        "score": score,
        "warnings": warnings,
    }

#make the path more presentable, gets ips and "from" that email passed through
def get_received(email):
    received_headers = email.get_all("Received", [])
    #print(email.get_all("Received", []))
    results = []

    for header in received_headers:
        match = re.search(r"from\s+(\S+).*?[\[(]([0-9a-fA-F:.]+)[\])]", header)
        if match:
            results.append({
                "server": match.group(1),
                "ip": match.group(2)
            })
        else:
            results.append({
                "server": None,
                "ip": None
            })

    return results

def get_authentication(email):
    authentication = email.get_all("Authentication-Results", [])
    return authentication

def get_url_warnings(url, hostname):
    warnings = []

    if url.lower().startswith("http://"):
        warnings.append("URL starts with HTTP rather than HTTPS.")

    try:
        ipaddress.ip_address(hostname)
        warnings.append("URL uses an IP address rather than a domain.")
    except ValueError:
        pass

    labels = hostname.split(".")

    for label in labels:
        if label.startswith("xn--"):
            try:
                decoded = label.encode("ascii").decode("idna")
                if not decoded:
                    raise UnicodeError
            except (UnicodeError, ValueError):
                warnings.append("Domain contains an invalid internationalized label.")
                break
            else:
                warnings.append("Domain contains an invalid internationalized label.")
                break
    return warnings