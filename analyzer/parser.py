from email import policy
from email.parser import Parser
import re

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
    regex = r'(?:https?://)?(?:www\.)?[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+(?:/[^\s<>"\']*)?'
    body_results = []
    urls = re.findall(regex, raw_body)
    for url in urls:
        body_results.append({"match": url})
    return body_results

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



