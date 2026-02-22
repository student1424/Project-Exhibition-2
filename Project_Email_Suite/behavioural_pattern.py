"""
Email Behavioral Pattern Analysis Module
Analyzes sender reputation through multiple DNS, WHOIS, and IP reputation checks
"""
import email 
from email import policy 
from email.parser import BytesParser 
import dns.resolver 
import requests 
import re 
import whois 
from datetime import datetime
import logging

# Configure logging
logger = logging.getLogger(__name__)

# Parse the raw email and extract sender and routing headers 
def parse_email(raw_email): 
    """Parse raw email and extract sender info and routing headers"""
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw_email) 
        sender = msg['From'] 
        received_headers = msg.get_all('Received', []) 
        return sender, received_headers 
    except Exception as e:
        logger.error(f"Email parsing error: {e}")
        return None, []

# Check if the domain has a valid SPF record 
def check_spf(domain): 
    """Verify if domain has valid SPF records"""
    try: 
        answers = dns.resolver.resolve(domain, 'TXT') 
        for rdata in answers: 
            if 'v=spf1' in rdata.to_text(): 
                return True 
    except Exception as e:
        logger.debug(f"SPF check failed for {domain}: {e}")
        return False 
    return False 

# Extract the sender IP address from the Received headers 
def extract_ip(headers): 
    """Extract sender IP from Received headers"""
    ip_pattern = r'\[(\d{1,3}(?:\.\d{1,3}){3})\]' 
    for h in headers: 
        match = re.search(ip_pattern, h) 
        if match: 
            return match.group(1) 
    return None 

# Use WHOIS to determine domain age in days 
def get_domain_age_local(domain): 
    """Get domain age in days from WHOIS data"""
    try: 
        w = whois.whois(domain) 
        creation_date = w.creation_date 
 
        # Handle list of dates 
        if isinstance(creation_date, list): 
            creation_date = next((d for d in creation_date if isinstance(d, datetime)), None) 
 
        # Final check 
        if not isinstance(creation_date, datetime): 
            logger.warning(f"WHOIS failed for {domain}: no valid creation date") 
            return -1 
 
        age_days = (datetime.now() - creation_date).days 
        return age_days 
    except Exception as e: 
        logger.error(f"Local WHOIS error for {domain}: {e}") 
        return -1 

# Check if the domain has MX records (mail server configuration) 
def has_mx_record(domain): 
    """Check if domain has valid MX records"""
    try: 
        answers = dns.resolver.resolve(domain, 'MX') 
        return len(answers) > 0 
    except Exception as e:
        logger.debug(f"MX check failed for {domain}: {e}")
        return False 

# Query VirusTotal for sender IP reputation 
def virustotal_check(ip, api_key=None): 
    """Check IP reputation against VirusTotal"""
    if not api_key:
        logger.warning("VirusTotal API key not provided")
        return 0
        
    try: 
        response = requests.get( 
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", 
            headers={"x-apikey": api_key},
            timeout=10
        ) 
        response.raise_for_status()
        data = response.json() 
        malicious_count = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0) 
        abuse_score = min(100, (malicious_count / 90) * 100) 
        return abuse_score 
    except Exception as e: 
        logger.error(f"VirusTotal API error: {e}") 
        return 0 

# Calculate a trust score based on multiple factors 
def score_sender(spf_valid, abuse_score, domain_age, mx_valid, sender, domain): 
    """Calculate comprehensive trust score (0-100)"""
    score = 100  # Start with full trust 
 
    # Technical signals 
    if not spf_valid: 
        score -= 30 
    if abuse_score > 50: 
        score -= 50 
    elif abuse_score > 20: 
        score -= 20 
    if domain_age != -1: 
        if domain_age < 30: 
            score -= 25 
        elif domain_age < 180: 
            score -= 10 
    if not mx_valid: 
        score -= 25 
 
    # Behavioral signals 
    if is_suspicious_name(sender): 
        score -= 20 
    if is_suspicious_domain(domain): 
        score -= 15 
 
    # Cap score between 0 and 100 
    score = max(0, min(score, 100)) 
    return score 

# Detect suspicious sender display names 
def is_suspicious_name(sender): 
    """Check for suspicious patterns in sender name"""
    return bool(re.search(r"(access log|#[A-Z0-9]{6,}|system alert|invoice|payment)", sender, re.IGNORECASE)) 

# Detect suspicious domains or TLDs 
def is_suspicious_domain(domain): 
    """Check for suspicious domain characteristics"""
    return domain.endswith('.ru') or domain.endswith('.cn') or len(domain) > 30 

# Main analysis function
def analyze_sender_reputation(raw_email, api_key=None):
    """
    Comprehensive sender reputation analysis
    Returns dict with analysis results
    """
    sender, headers = parse_email(raw_email) 
    
    if not sender:
        return {"error": "Failed to parse email"}
    
    domain = sender.split('@')[-1]  
    domain = re.sub(r"[^\w\.-]", "", domain.strip().lower()) 
    
    domain_age = get_domain_age_local(domain) 
    mx_valid = has_mx_record(domain) 
    spf_valid = check_spf(domain) 
    ip = extract_ip(headers) 
    abuse_score = virustotal_check(ip, api_key) if ip else 0
    trust_score = score_sender(spf_valid, abuse_score, domain_age, mx_valid, sender, domain) 
    
    return {
        "sender": sender,
        "domain": domain,
        "ip": ip,
        "spf_valid": spf_valid,
        "virustotal_score": abuse_score,
        "domain_age_days": domain_age,
        "mx_valid": mx_valid,
        "trust_score": trust_score,
        "risk_level": "Low" if trust_score > 80 else "Medium" if trust_score > 50 else "High",
        "is_suspicious_name": is_suspicious_name(sender),
        "is_suspicious_domain": is_suspicious_domain(domain)
    }