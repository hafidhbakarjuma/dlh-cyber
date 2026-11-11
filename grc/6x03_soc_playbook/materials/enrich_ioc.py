#!/usr/bin/env python3
import sys
import json
import socket
import ipaddress
import re
from datetime import datetime, timezone
import argparse
from urllib.parse import urlparse

def detect_ioc_type(value: str) -> str:
    """Detects if the IOC is ipv4, ipv6, domain, or url. Extracts hostname for URLs."""
    value = value.strip()
    # Check if URL
    if "://" in value or value.startswith("www."):
        parsed = urlparse(value if "://" in value else "http://" + value)
        if parsed.hostname:
            return "url"
    
    # Check if IP address
    try:
        ip = ipaddress.ip_address(value)
        if isinstance(ip, ipaddress.IPv4Address):
            return "ipv4"
        elif isinstance(ip, ipaddress.IPv6Address):
            return "ipv6"
    except ValueError:
        pass
    
    return "domain"

def classify_ip(ip_str: str) -> str:
    """Classifies IP address into private, loopback, link_local, documentation, multicast, or public."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return "unknown"
    
    # Explicit documentation ranges check (RFC 5737 / RFC 3849)
    doc_networks = [
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
        ipaddress.ip_network("2001:db8::/32")
    ]
    for net in doc_networks:
        if ip in net:
            return "documentation"
            
    if ip.is_private:
        return "private"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link_local"
    if ip.is_multicast:
        return "multicast"
    
    return "public"

def reverse_dns(ip: str) -> str:
    """Performs reverse DNS lookup with a 3-second timeout."""
    socket.setdefaulttimeout(3)
    try:
        ipaddress.ip_address(ip)
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except ValueError:
        return "N/A"
    except socket.herror:
        return "NXDOMAIN"
    except socket.timeout:
        return "TIMEOUT"
    except Exception:
        return "NXDOMAIN"

def check_feed(value: str, feed: dict) -> dict:
    """Looks up value across malicious and benign feeds."""
    val_to_check = value.strip()
    if detect_ioc_type(val_to_check) == "url":
        parsed = urlparse(val_to_check if "://" in val_to_check else "http://" + val_to_check)
        val_to_check = parsed.hostname or val_to_check

    malicious_ips = feed.get("malicious_ips", {})
    malicious_domains = feed.get("malicious_domains", {})
    benign_ips = feed.get("benign_ips", {})
    benign_domains = feed.get("benign_domains", {})

    result = {
        "in_malicious_feed": False,
        "in_benign_list": False
    }

    if val_to_check in malicious_ips:
        result["in_malicious_feed"] = True
        result.update(malicious_ips[val_to_check])
    elif val_to_check in malicious_domains:
        result["in_malicious_feed"] = True
        result.update(malicious_domains[val_to_check])
    elif val_to_check in benign_ips:
        result["in_benign_list"] = True
        result.update(benign_ips[val_to_check])
    elif val_to_check in benign_domains:
        result["in_benign_list"] = True
        result.update(benign_domains[val_to_check])

    return result

def score_ioc(feed_result: dict, ip_class: str) -> tuple[int, str]:
    """Calculates risk score and returns verdict (BLOCK, INVESTIGATE, ALLOW)."""
    if ip_class in ["private", "loopback"]:
        return 0, "ALLOW"
    if feed_result.get("in_benign_list", False):
        return 0, "ALLOW"
    
    if feed_result.get("in_malicious_feed", False):
        confidence = feed_result.get("confidence", 50)
        if confidence >= 80:
            return confidence, "BLOCK"
        else:
            return confidence, "INVESTIGATE"
            
    # Default for unknown public IPs or domains not in feeds
    return 30, "INVESTIGATE"

def enrich_ioc(value: str, feed_path: str = "ioc_feed.json") -> dict:
    """Main enrichment function that loads feed, classifies, and returns structured JSON verdict."""
    try:
        with open(feed_path, "r") as f:
            feed = json.load(f)
    except Exception:
        feed = {}

    ioc_type = detect_ioc_type(value)
    
    lookup_val = value.strip()
    if ioc_type == "url":
        parsed = urlparse(lookup_val if "://" in lookup_val else "http://" + lookup_val)
        lookup_target = parsed.hostname or lookup_val
    else:
        lookup_target = lookup_val

    ip_class = "N/A"
    rev_dns = "N/A"
    
    if ioc_type in ["ipv4", "ipv6"]:
        ip_class = classify_ip(lookup_target)
        rev_dns = reverse_dns(lookup_target)
    elif ioc_type == "url":
        try:
            ipaddress.ip_address(lookup_target)
            ip_class = classify_ip(lookup_target)
            rev_dns = reverse_dns(lookup_target)
        except ValueError:
            pass

    feed_result = check_feed(lookup_target, feed)
    score, verdict = score_ioc(feed_result, ip_class)

    enriched_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    result = {
        "ioc": value.strip(),
        "type": ioc_type,
        "ip_class": ip_class,
        "reverse_dns": rev_dns,
        "feed_result": feed_result,
        "score": score,
        "verdict": verdict,
        "enriched_at": enriched_at
    }

    if ip_class in ["private", "loopback"]:
        if ip_class == "private":
            result["note"] = "Private address range; internal network traffic"
        else:
            result["note"] = "Loopback address range"

    return result

def main():
    parser = argparse.ArgumentParser(description="IOC Enrichment Engine CLI")
    parser.add_argument("ioc", nargs="?", help="Single IOC to enrich (IP, domain, or URL)")
    parser.add_argument("--batch", help="Path to file containing one IOC per line")
    parser.add_argument("--output", help="Path to output JSON file for batch mode")
    parser.add_argument("--feed", default="ioc_feed.json", help="Path to threat intel feed JSON")

    args = parser.parse_args()

    if args.batch:
        iocs = []
        try:
            with open(args.batch, "r") as f:
                iocs = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"Error reading batch file {args.batch}: {e}", file=sys.stderr)
            sys.exit(1)

        results = []
        counts = {"Processed": len(iocs), "BLOCK": 0, "INVESTIGATE": 0, "ALLOW": 0}

        for ioc in iocs:
            res = enrich_ioc(ioc, feed_path=args.feed)
            results.append(res)
            verdict = res.get("verdict", "INVESTIGATE")
            if verdict in counts:
                counts[verdict] += 1

        if args.output:
            with open(args.output, "w") as f:
                json.dump(results, f, indent=2)

        summary_str = f"Processed: {counts['Processed']} | BLOCK: {counts['BLOCK']} | INVESTIGATE: {counts['INVESTIGATE']} | ALLOW: {counts['ALLOW']}"
        print(summary_str)

    elif args.ioc:
        res = enrich_ioc(args.ioc, feed_path=args.feed)
        print(json.dumps(res, indent=2))
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
