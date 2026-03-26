"""
threat_engine.py
================
Multi-Signal Email Threat Classification Engine
Implements a 5-layer Gmail-grade classification pipeline:
  Layer 2a: Weighted keyword / phrase scoring
  Layer 2b: HTML structure analysis (hidden text, href mismatch, forms, data URIs)
  Layer 2c: URL analysis  (shorteners, IP URLs, lookalike / typosquatting domains)
  Layer 2e: SimHash content fingerprinting against known-threat corpus
  Layer 3:  Sender / Reply-To analysis
  Layer 4:  Existing Isolation Forest + Random Forest models
  Layer 5:  Weighted scoring aggregator + threshold-based decision engine
"""

import re
import json
import hashlib
import os
from urllib.parse import urlparse
from typing import Tuple, List, Optional
from bs4 import BeautifulSoup

# Extended rule sets and negative scoring (kept separate to avoid corruption)
try:
    from threat_rules import SPAM_EXTRA, PHISHING_EXTRA, BEC_EXTRA, NEGATIVE_RULES, EXTRA_OBFUSCATION
    _RULES_LOADED = True
except Exception:
    SPAM_EXTRA = PHISHING_EXTRA = BEC_EXTRA = {}
    NEGATIVE_RULES = {}
    EXTRA_OBFUSCATION = []
    _RULES_LOADED = False

# Live threat-feed lookups (OpenPhish, URLhaus, optional VirusTotal/GSB)
try:
    import threat_intel as _ti
    _FEEDS_AVAILABLE = True
except Exception:
    _FEEDS_AVAILABLE = False

# =============================================================================
# LAYER 2a — WEIGHTED KEYWORD / PHRASE SCORING
# =============================================================================

SPAM_WEIGHTED = {
    # Critical (0.80–0.90)
    'you have won':                     0.88,
    'you are a winner':                 0.88,
    'claim your prize':                 0.88,
    'dear winner':                      0.88,
    'lottery winner':                   0.88,
    'congratulations you have been selected': 0.85,
    'congratulations you have won':     0.90,
    'nigerian prince':                  0.95,
    'unclaimed funds':                  0.82,
    'inheritance funds':                0.82,
    'you have been chosen':             0.80,
    'secret shopper':                   0.78,
    'click here to claim':              0.82,
    'hot singles near you':             0.92,
    'adult content':                    0.75,
    'meet singles':                     0.78,
    'viagra':                           0.88,
    'cialis':                           0.88,
    'online pharmacy':                  0.78,
    'prescription drugs no prescription': 0.85,
    'cheap meds':                       0.80,
    'male enhancement':                 0.85,
    'enlarge your':                     0.88,
    # High (0.60–0.79)
    'billion dollars':                  0.70,
    'million dollars':                  0.65,
    'make money fast':                  0.72,
    'earn extra cash':                  0.68,
    'work from home':                   0.55,
    'no credit card required':          0.58,
    'money back guarantee':             0.52,
    'limited time offer':               0.55,
    '100% guarantee':                   0.58,
    'pre-approved':                     0.65,
    'you have been selected':           0.65,
    'free gift':                        0.52,
    'free trial':                       0.48,
    'special promotion':                0.48,
    'risk free':                        0.52,
    'act now':                          0.50,
    'weight loss':                      0.58,
    'diet pill':                        0.65,
    'this is not spam':                 0.75,
    'if you wish to unsubscribe':       0.55,
    'click below to unsubscribe':       0.58,
}

PHISHING_WEIGHTED = {
    # Critical
    'verify your account immediately':          0.92,
    'your account has been suspended':          0.92,
    'your account will be closed':              0.90,
    'your account will be terminated':          0.90,
    'click the link below to verify':           0.90,
    'click here to secure your account':        0.90,
    'apple id suspended':                       0.92,
    'apple id has been locked':                 0.92,
    'apple id has been disabled':               0.92,
    'apple id has been locked':                 0.92,
    'google account suspended':                 0.92,
    'paypal account limited':                   0.92,
    'update your billing information':          0.88,
    'your password has expired':                0.88,
    'reset your password immediately':          0.88,
    'irs notice':                               0.85,
    'tax refund':                               0.78,
    'hmrc refund':                              0.85,
    # High
    'confirm your account':                     0.80,
    'unusual activity detected':                0.82,
    'suspicious activity detected':             0.82,
    'suspicious sign-in':                       0.82,
    'security alert':                           0.75,
    'sign in to verify':                        0.82,
    'enter your credentials':                   0.80,
    'provide your details':                     0.72,
    'verify your identity':                     0.72,
    'identity verification required':           0.78,
    'login attempt was made':                   0.82,
    'failed login attempt':                     0.78,
    'your bank account needs':                  0.85,
    'chase bank alert':                         0.85,
    'your paypal account':                      0.72,
    'docusign':                                 0.55,
}

BEC_WEIGHTED = {
    # Critical
    'wire the funds':                   0.95,
    'please wire':                      0.88,
    'itunes gift card':                 0.92,
    'google play card':                 0.90,
    'steam gift card':                  0.90,
    'amazon gift card':                 0.88,
    'purchase gift cards':              0.92,
    'change bank details':              0.92,
    'new banking details':              0.92,
    'new account details':              0.88,
    'direct deposit change':            0.88,
    'do not discuss with anyone':       0.88,
    "don't tell anyone about this":     0.85,
    'deal must close today':            0.85,
    'acquisition is underway':          0.85,
    'confidential transaction':         0.85,
    # High
    'wire transfer':                    0.82,
    'gift card':                        0.75,
    'please process payment':           0.82,
    'executive request':                0.75,
    'strictly confidential':            0.68,
    'payroll update':                   0.72,
    'voided check':                     0.78,
    'i need you to purchase':           0.78,
    'are you at your desk':             0.62,
    'ceo has approved':                 0.88,
}

# Obfuscation regex: catches deliberate letter substitution
OBFUSCATION_PATTERNS = [
    (r'v[\W_]*[i1][\W_]*[a4][\W_]*g[\W_]*r[\W_]*[a4]', 0.85),
    (r'c[\W_]*[i1][\W_]*[a4][\W_]*l[\W_]*[i1][\W_]*s', 0.85),
    (r'c[a4]sh[\W_]*[a4]dv[a4]nce', 0.70),
    (r'fr[\W_]*[3e][3e]', 0.62),
    (r'[a4]cc[\W_]*[0o]unt', 0.68),
    (r'p[\W_]*[a4][\W_]*ss[\W_]*w[\W_]*[o0]rd', 0.65),
    (r'[s$][\W_]*[3e][\W_]*[x×]', 0.88),
    (r'l[o0][t+]t[e3]ry', 0.78),
]

# ===========================================================================
# LAYER 2c — URL constants
# ===========================================================================

BRAND_DOMAINS = [
    'paypal.com', 'amazon.com', 'google.com', 'microsoft.com', 'apple.com',
    'facebook.com', 'netflix.com', 'chase.com', 'wellsfargo.com',
    'bankofamerica.com', 'irs.gov', 'ebay.com', 'instagram.com',
    'twitter.com', 'linkedin.com', 'dropbox.com', 'icloud.com',
    'outlook.com', 'office.com', 'docusign.com', 'fedex.com', 'ups.com',
    'dhl.com', 'usps.com', 'americanexpress.com', 'citibank.com',
]

URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd', 'tiny.cc',
    't.co', 'buff.ly', 'dlvr.it', 'ift.tt', 'adf.ly', 'short.link',
    'cutt.ly', 'rb.gy', 'shorturl.at', 'clck.ru', 'lnk.to', 'bl.ink',
}

FREE_PROVIDERS = {
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
    'aol.com', 'protonmail.com', 'icloud.com', 'yandex.com', 'mail.com',
}

# =============================================================================
# SIBLING HELPER: Levenshtein distance (pure Python — no external lib needed)
# =============================================================================

def _levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if not s2:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for c1 in s1:
        curr = [prev[0] + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[-1] + 1, prev[j] + (c1 != c2)))
        prev = curr
    return prev[-1]


# =============================================================================
# LAYER 2e — SIMHASH CONTENT FINGERPRINTING
# =============================================================================

class SimHash:
    """Pure-Python 64-bit SimHash for near-duplicate detection."""
    BITS = 64

    def __init__(self, text: str, shingle_size: int = 3):
        tokens = re.findall(r'\w+', text.lower())
        shingles = (
            [' '.join(tokens[i:i + shingle_size])
             for i in range(max(1, len(tokens) - shingle_size + 1))]
            if tokens else ['']
        )
        v = [0] * self.BITS
        for s in shingles:
            h = int(hashlib.md5(s.encode('utf-8', errors='ignore')).hexdigest(), 16)
            h &= (1 << self.BITS) - 1
            for i in range(self.BITS):
                v[i] += 1 if (h >> i) & 1 else -1
        self._hash = sum(1 << i for i in range(self.BITS) if v[i] > 0)

    def similarity(self, other: 'SimHash') -> float:
        return 1.0 - bin(self._hash ^ other._hash).count('1') / self.BITS

    def to_hex(self) -> str:
        return format(self._hash, '016x')

    @classmethod
    def from_hex(cls, h: str) -> 'SimHash':
        obj = cls.__new__(cls)
        obj._hash = int(h, 16)
        return obj


# Known spam/phishing seed texts — fingerprint DB is seeded from these at startup
_SEED_TEMPLATES = [
    ('SPAM',     'nigerian_prince',
     "I am a Nigerian prince and I need your assistance to transfer 45 million dollars out of my country. "
     "I will give you 30 percent of the total sum for your help. Please reply with your bank details urgently."),
    ('SPAM',     'lottery_win',
     "CONGRATULATIONS! You have won the international lottery draw! Your email was selected from millions. "
     "You have won 1000000 USD. To claim your prize contact our lottery agent and provide your full name "
     "address telephone number and bank account details."),
    ('SPAM',     'inheritance',
     "I am the attorney to a late client who died intestate leaving a fund of 18.5 million dollars. "
     "I seek your cooperation to claim these unclaimed funds as next of kin. You will receive 40 percent "
     "for your cooperation. Please reply with your full name and bank account information."),
    ('SPAM',     'work_from_home',
     "Make money from home! Earn 500 to 1000 dollars per day working online. No experience needed. "
     "Limited positions available. Act now to secure your spot. Sign up free today risk free offer."),
    ('SPAM',     'weight_loss',
     "Lose 30 pounds in 30 days with our revolutionary new diet pill! No exercise required! "
     "100% guaranteed results or your money back! Limited time offer order now and get a free gift!"),
    ('SPAM',     'online_pharmacy',
     "Buy cheap medications online without prescription! Viagra Cialis and more at the lowest prices. "
     "100% satisfaction guaranteed. Free shipping worldwide. No prior prescription needed. Order now!"),
    ('SPAM',     'selected_winner',
     "You have been selected as a winner of our grand prize draw! Congratulations you have won an iPhone. "
     "To claim your prize click here now! Limited time offer you are a winner! Claim your prize today!"),
    ('PHISHING', 'paypal_suspended',
     "Dear Customer your PayPal account has been suspended due to unusual activity detected on your account. "
     "Please verify your account immediately by clicking the link below to restore access. "
     "Failure to verify within 24 hours will result in permanent suspension of your account."),
    ('PHISHING', 'bank_suspended',
     "Your bank account has been temporarily suspended due to suspicious activity. Please login immediately "
     "to verify your identity and restore account access. Click here to secure your account and update "
     "your billing information."),
    ('PHISHING', 'irs_refund',
     "IRS Notice you are eligible for a tax refund. To claim your refund you must verify your identity "
     "by providing your Social Security Number date of birth and bank account details. Act now."),
    ('PHISHING', 'apple_suspended',
     "Your Apple ID has been suspended. Unusual sign-in activity was detected on your account. "
     "Please sign in to verify your identity. Click the link below to restore your Apple ID "
     "account access and update your payment information."),
    ('PHISHING', 'password_expired',
     "Your password has expired and your account is at risk. Reset your password immediately by clicking "
     "the link below. Failure to reset within 24 hours will lock your account. Enter your credentials."),
    ('PHISHING', 'microsoft_phishing',
     "Your Microsoft account has been flagged for suspicious activity. Your account will be locked unless "
     "you verify your account immediately. Click the link to confirm your identity and login credentials now."),
    ('PHISHING', 'google_phishing',
     "Google Security Alert: A new sign-in to your Google Account was detected. If you did not sign in "
     "click here to secure your account now. Review activity and verify your identity immediately."),
    ('PHISHING', 'amazon_phishing',
     "Your Amazon order has been placed on hold due to payment verification required. Please verify your "
     "billing information and confirm your payment details to release your order. Update your account now."),
    ('PHISHING', 'docusign_phishing',
     "You have a document awaiting your electronic signature. Please review and sign the document immediately. "
     "Click the link below to access your document. Your account credentials are required to verify your identity."),
    ('BEC',      'gift_card',
     "Hi are you available right now? I need you to purchase 10 iTunes gift cards for a client presentation. "
     "I am in a meeting and cannot be reached by phone. Do not discuss with anyone. Send me the card codes ASAP."),
    ('BEC',      'wire_transfer',
     "URGENT please wire 75000 dollars to the vendor account immediately. The CEO has approved this transfer. "
     "This is strictly confidential do not discuss with anyone. Please process this wire transfer today "
     "and confirm when done. New banking details are attached."),
    ('BEC',      'invoice_fraud',
     "Please update our bank account details for future payments. We have changed our banking information. "
     "Please use the new account details for the next invoice payment. Do not share this information."),
    ('BEC',      'ceo_fraud',
     "This is a confidential request from the executive team. We are in the process of a company acquisition. "
     "I need you to initiate a wire transfer to our legal account today. Do not mention this to anyone "
     "in the office. Confirm when the transfer is complete. This is strictly confidential."),
]


class FingerprintDB:
    """Persistent fingerprint database of known spam/phishing content."""
    DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           'data', 'threat_fingerprints.json')
    THRESHOLD = 0.72

    def __init__(self):
        self._db = self._load()

    def _load(self) -> dict:
        if os.path.exists(self.DB_PATH):
            try:
                with open(self.DB_PATH, 'r') as f:
                    return json.load(f)
            except Exception:
                pass
        # Seed from built-in templates
        db = {'version': 2, 'fingerprints': []}
        for label, name, text in _SEED_TEMPLATES:
            db['fingerprints'].append({
                'hash': SimHash(text).to_hex(),
                'label': label,
                'name': name,
            })
        self._save(db)
        return db

    def _save(self, db: dict):
        os.makedirs(os.path.dirname(self.DB_PATH), exist_ok=True)
        with open(self.DB_PATH, 'w') as f:
            json.dump(db, f, indent=2)

    def check(self, text: str) -> Tuple[float, Optional[str]]:
        """Returns (best_similarity, matched_label) — (0.0, None) if no match."""
        sh = SimHash(text)
        best_sim, best_label = 0.0, None
        for entry in self._db.get('fingerprints', []):
            try:
                stored = SimHash.from_hex(entry['hash'])
                sim = sh.similarity(stored)
                if sim > best_sim:
                    best_sim, best_label = sim, entry['label']
            except Exception:
                continue
        if best_sim >= self.THRESHOLD:
            return round(best_sim, 4), best_label
        return 0.0, None

    def add(self, text: str, label: str, name: str = 'user_reported'):
        """Add a user-reported fingerprint to the database."""
        self._db['fingerprints'].append({
            'hash': SimHash(text).to_hex(),
            'label': label,
            'name': name,
        })
        self._save(self._db)


# =============================================================================
# LAYER 2a — KEYWORD ANALYSIS (function)
# =============================================================================

def _score_keywords(text: str) -> Tuple[float, List[str]]:
    text_lower = text.lower()
    signals, total = [], 0.0

    # Merge base + extended rule sets
    all_positive = {**SPAM_WEIGHTED, **PHISHING_WEIGHTED, **BEC_WEIGHTED,
                    **SPAM_EXTRA, **PHISHING_EXTRA, **BEC_EXTRA}

    # Weighted phrase matching (positive rules)
    for phrase, weight in all_positive.items():
        if phrase in text_lower:
            total += weight
            signals.append(f'KEYWORD: "{phrase}"')

    # Negative rules: reduce score for legitimate email signals
    neg_total = 0.0
    for phrase, weight in NEGATIVE_RULES.items():
        if phrase in text_lower:
            neg_total += weight   # weight is already negative
    # Cap deduction: never reduce by more than 40% of the positive total
    if total > 0:
        max_deduction = total * 0.40
        neg_total = max(neg_total, -max_deduction)
    total = max(0.0, total + neg_total)

    # Obfuscation detection (base patterns + extended patterns)
    for pattern, weight in OBFUSCATION_PATTERNS + EXTRA_OBFUSCATION:
        if re.search(pattern, text_lower):
            total += weight
            signals.append('OBFUSCATION_DETECTED')
            break

    # BEC cluster boost: 2+ BEC phrases → extra weight
    bec_hits = sum(1 for p in {**BEC_WEIGHTED, **BEC_EXTRA} if p in text_lower)
    if bec_hits >= 2:
        total += 0.45
        signals.append('MULTIPLE_BEC_SIGNALS')

    score = min(1.0, total / 3.5)
    return score, signals[:15]



# =============================================================================
# LAYER 2b — HTML STRUCTURE ANALYSIS
# =============================================================================

def _analyze_html(html_body: str) -> Tuple[float, List[str]]:
    if not html_body or not html_body.strip():
        return 0.0, []
    signals, score = [], 0.0
    try:
        soup = BeautifulSoup(html_body, 'html.parser')

        # 1. Hidden text tricks
        for elem in soup.find_all(style=True):
            s = elem.get('style', '').lower().replace(' ', '')
            if ('font-size:0' in s or 'color:#fff' in s or
                    'color:white' in s or 'display:none' in s or
                    'visibility:hidden' in s):
                signals.append('HTML_HIDDEN_TEXT')
                score += 0.65
                break

        # 2. Href vs display-URL mismatch
        for a in soup.find_all('a', href=True):
            href = a.get('href', '')
            display = a.get_text().strip()
            if href.startswith('http') and re.search(r'[\w-]+\.\w{2,}', display):
                try:
                    href_host = urlparse(href).netloc.replace('www.', '')
                    m = re.search(r'[\w-]+\.\w{2,}', display)
                    if m:
                        disp_host = m.group().replace('www.', '')
                        if disp_host and href_host and disp_host != href_host:
                            signals.append('HTML_HREF_MISMATCH')
                            score += 0.75
                            break
                except Exception:
                    pass

        # 3. Credential harvesting form
        for form in soup.find_all('form'):
            if form.find('input', type=['password', 'text']):
                signals.append('HTML_CREDENTIAL_FORM')
                score += 0.85
                break

        # 4. Data URI obfuscation
        for elem in soup.find_all(['a', 'img', 'iframe']):
            for attr in ['href', 'src']:
                if elem.get(attr, '').startswith('data:'):
                    signals.append('HTML_DATA_URI')
                    score += 0.65
                    break

        # 5. Image spam: many images, almost no text
        imgs = soup.find_all('img')
        words = len(re.findall(r'\w+', soup.get_text()))
        if len(imgs) >= 2 and words < 25:
            signals.append('HTML_IMAGE_SPAM')
            score += 0.50

    except Exception:
        pass
    return min(1.0, score), signals


# =============================================================================
# LAYER 2c — URL ANALYSIS
# =============================================================================

def _extract_urls(text: str, html_body: str = '') -> List[str]:
    found = set()
    pat = re.compile(r'https?://[^\s<>"\'`\)]+|www\.[^\s<>"\'`\)]+', re.I)
    for u in pat.findall(text):
        found.add(u.rstrip('.,;:!)>'))
    if html_body:
        try:
            soup = BeautifulSoup(html_body, 'html.parser')
            for a in soup.find_all('a', href=True):
                h = a['href']
                if h.startswith(('http', 'www.')):
                    found.add(h.rstrip('.,;:!'))
        except Exception:
            pass
    return list(found)


def _analyze_urls(text: str, html_body: str = '') -> Tuple[float, List[str], List[str]]:
    urls = _extract_urls(text, html_body)
    if not urls:
        return 0.0, [], []

    signals, flagged, score = [], [], 0.0

    for url in urls[:20]:
        try:
            parsed = urlparse(url if '://' in url else 'http://' + url)
            domain = parsed.netloc.lower().replace('www.', '').split(':')[0]
        except Exception:
            continue
        if not domain:
            continue

        base = '.'.join(domain.split('.')[-2:]) if '.' in domain else domain

        # Shortener
        if base in URL_SHORTENERS or domain in URL_SHORTENERS:
            signals.append('URL_SHORTENER')
            flagged.append(url)
            score += 0.50
            continue

        # IP-address URL
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain):
            signals.append('URL_IP_ADDRESS')
            flagged.append(url)
            score += 0.75
            continue

        # Lookalike / typosquatting
        parts = domain.split('.')
        if len(parts) >= 2:
            check = parts[-2]
            for brand in BRAND_DOMAINS:
                brand_root = brand.split('.')[0]
                if check == brand_root:
                    break  # exact — legitimate
                if len(brand_root) > 4 and _levenshtein(check, brand_root) <= 2:
                    signals.append(f'LOOKALIKE_DOMAIN:{domain}≈{brand}')
                    flagged.append(url)
                    score += 0.80
                    break

        # Brand name buried in subdomains (paypal.malicious.ru)
        for brand in BRAND_DOMAINS:
            brand_root = brand.split('.')[0]
            if brand_root in parts[:-2] and not domain.endswith(brand):
                signals.append(f'BRAND_SUBDOMAIN_ABUSE:{domain}')
                flagged.append(url)
                score += 0.85
                break

        # Excessive subdomains (≥4 dots)
        if domain.count('.') >= 4:
            signals.append('EXCESSIVE_SUBDOMAINS')
            flagged.append(url)
            score += 0.55

    # Optional: PhishTank
    pt_key = os.environ.get('PHISHTANK_API_KEY', '')
    if pt_key:
        try:
            import requests as _r
            for url in urls[:5]:
                r = _r.post('https://checkurl.phishtank.com/checkurl/',
                             data={'url': url, 'format': 'json', 'app_key': pt_key},
                             timeout=2)
                if r.ok:
                    d = r.json().get('results', {})
                    if d.get('in_database') and d.get('valid'):
                        signals.append('PHISHTANK_HIT')
                        flagged.append(url)
                        score = max(score, 0.95)
        except Exception:
            pass

    # Optional: Google Safe Browsing
    gsb_key = os.environ.get('GOOGLE_SAFE_BROWSING_KEY', '')
    if gsb_key and urls:
        try:
            import requests as _r
            payload = {
                'client': {'clientId': 'email-threat-detector', 'clientVersion': '2.0'},
                'threatInfo': {
                    'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
                    'platformTypes': ['ANY_PLATFORM'],
                    'threatEntryTypes': ['URL'],
                    'threatEntries': [{'url': u} for u in urls[:10]],
                },
            }
            r = _r.post(
                f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={gsb_key}',
                json=payload, timeout=2,
            )
            if r.ok and r.json().get('matches'):
                signals.append('GOOGLE_SAFE_BROWSING_HIT')
                score = max(score, 0.95)
        except Exception:
            pass

    # ── Layer 2d: Live threat feed check (OpenPhish, URLhaus) ─────────────────
    # This is the most impactful check — catches copy-paste phishing URLs
    # that exist in crowdsourced threat databases even from clean senders.
    if _FEEDS_AVAILABLE and urls:
        try:
            feed_hit, feed_src, feed_flagged = _ti.check_urls_batch(urls)
            if feed_hit:
                signals.append(f'LIVE_FEED_HIT:{feed_src}')
                flagged.extend(feed_flagged)
                score = max(score, 0.95)
        except Exception:
            pass

    dedup_signals = list(dict.fromkeys(signals))
    dedup_urls    = list(dict.fromkeys(flagged))
    return min(1.0, score), dedup_signals[:12], dedup_urls[:12]



# =============================================================================
# LAYER 3 — SENDER ANALYSIS
# =============================================================================

def _analyze_sender(sender: str, reply_to: str = '') -> Tuple[float, List[str]]:
    if not sender:
        return 0.0, []
    signals, score = [], 0.0

    def _extract_email(s):
        m = re.search(r'<([^>]+)>', s)
        return m.group(1).lower() if m else s.lower().strip()

    def _domain(email):
        return email.split('@')[-1] if '@' in email else ''

    sender_email  = _extract_email(sender)
    sender_domain = _domain(sender_email)
    display_name  = re.sub(r'<[^>]+>', '', sender).strip().lower()

    # Reply-To mismatch
    if reply_to:
        rt_domain = _domain(_extract_email(reply_to))
        if rt_domain and sender_domain and rt_domain != sender_domain:
            signals.append('REPLY_TO_DOMAIN_MISMATCH')
            score += 0.40
            if rt_domain in FREE_PROVIDERS and sender_domain not in FREE_PROVIDERS:
                signals.append('REPLY_TO_FREE_PROVIDER')
                score += 0.30

    # Display name impersonating a brand
    for brand in BRAND_DOMAINS:
        brand_name = brand.split('.')[0]
        if brand_name in display_name and not sender_domain.endswith(brand):
            signals.append(f'SENDER_IMPERSONATION:{brand_name}')
            score += 0.65
            break

    return min(1.0, score), signals


# =============================================================================
# LAYER 4 — ML MODEL SCORING
# =============================================================================

def _extract_features(text: str) -> list:
    """Duplicate of the feature extractor so threat_engine has no circular imports."""
    if not isinstance(text, str):
        text = str(text)
    length    = len(text)
    text_l    = text.lower()
    words     = re.findall(r'\b\w+\b', text_l)
    html_tags = len(re.findall(r'<[^>]+>', text))
    urls      = len(re.findall(r'(https?://|www\.)', text_l))
    excl      = text.count('!')
    dollar    = text.count('$')
    uppers    = sum(1 for c in text if c.isupper())
    upper_r   = uppers / length if length > 0 else 0
    urgent_w  = text_l.count('urgent') + text_l.count('immediate') + text_l.count('action required')
    acct_w    = text_l.count('account') + text_l.count('suspend') + text_l.count('verify')
    digits    = sum(1 for c in text if c.isdigit())
    lex_div   = len(set(words)) / len(words) if words else 0
    login_w   = text_l.count('password') + text_l.count('login') + text_l.count('secure') + text_l.count('locked')
    reward_w  = text_l.count('free') + text_l.count('prize') + text_l.count('guaranteed') + text_l.count('winner')
    short_w   = len(re.findall(r'(bit\.ly|tinyurl\.com|goo\.gl|ow\.ly|is\.gd|tiny\.cc)', text_l))
    excess_p  = len(re.findall(r'[\?\*\#\@]{2,}', text))
    avg_wl    = sum(len(w) for w in words) / len(words) if words else 0
    return [length, html_tags, urls, excl, dollar, upper_r, urgent_w, acct_w,
            digits, lex_div, login_w, reward_w, short_w, excess_p, avg_wl]


def _ml_score(text: str, iso_model, scaler, rf_model) -> Tuple[float, List[str]]:
    if not all([iso_model, scaler, rf_model]):
        return 0.10, []
    try:
        import numpy as np
        features = _extract_features(text)
        arr      = np.array(features).reshape(1, -1)
        scaled   = scaler.transform(arr)
        iso_s    = float(iso_model.decision_function(scaled)[0])
        stacked  = np.hstack((arr[0], [iso_s])).reshape(1, -1)
        pred     = int(rf_model.predict(stacked)[0])
        base     = {0: 0.10, 1: 0.75, 2: 0.70}.get(pred, 0.10)
        if iso_s < -0.15:
            base = min(1.0, base + 0.10)
        sigs = [] if pred == 0 else ['ML_MODEL_THREAT_DETECTED']
        return round(base, 4), sigs
    except Exception:
        return 0.10, []


# =============================================================================
# LAYER 5 — SCORING AGGREGATOR & CLASSIFICATION
# =============================================================================

def _classify(score: float) -> Tuple[str, str, str]:
    if score < 0.30:
        return 'SAFE',      'LOW',      'ALLOW'
    if score < 0.50:
        return 'SUSPICIOUS','MEDIUM',   'REVIEW'
    if score < 0.70:
        return 'SPAM',      'HIGH',     'QUARANTINE'
    if score < 0.85:
        return 'PHISHING',  'HIGH',     'BLOCK'
    return     'MALWARE',   'CRITICAL', 'BLOCK'


def _to_legacy(c: str) -> str:
    return {
        'SAFE':       'Safe',
        'SUSPICIOUS': 'Suspicious',
        'SPAM':       'Phishing',
        'PHISHING':   'Phishing',
        'MALWARE':    'Phishing',
    }.get(c, 'Phishing')


def _build_explanation(classification: str, signals: List[str],
                        flagged_urls: List[str], fp_sim: float) -> str:
    parts = []
    if fp_sim > 0:
        parts.append(f"Content matches a known {classification.lower()} template "
                     f"({fp_sim * 100:.0f}% similarity to threat corpus).")
    if any('PHISHTANK' in s or 'SAFE_BROWSING' in s for s in signals):
        parts.append("One or more URLs confirmed malicious via threat intelligence feeds.")
    if any('HREF_MISMATCH' in s for s in signals):
        parts.append("Displayed link URL differs from actual hyperlink destination — classic phishing tactic.")
    if any('LOOKALIKE' in s for s in signals):
        parts.append("A URL closely resembles a trusted brand domain (typosquatting).")
    if any('BRAND_SUBDOMAIN' in s for s in signals):
        parts.append("A trusted brand name is buried inside a suspicious domain.")
    if any('CREDENTIAL_FORM' in s for s in signals):
        parts.append("Email contains a credential-collection form — legitimate services never use this.")
    if any('HIDDEN_TEXT' in s for s in signals):
        parts.append("HTML hidden-text tricks detected — a common scanner evasion technique.")
    if any('BEC' in s for s in signals):
        parts.append("Multiple Business Email Compromise signals identified.")
    if any('KEYWORD' in s for s in signals) and not parts:
        parts.append("Multiple high-risk spam/phishing phrases detected in content.")
    if classification == 'SAFE':
        return "No significant threat signals detected. Email content appears legitimate."
    return ' '.join(parts) or f"Aggregated multi-signal analysis classified this as {classification}."


# =============================================================================
# PUBLIC API — ThreatEngine
# =============================================================================

class ThreatEngine:
    """
    Main entry point. Instantiate once at app startup, then call classify().
    """

    def __init__(self, iso_model=None, scaler=None, rf_model=None):
        self._iso   = iso_model
        self._sc    = scaler
        self._rf    = rf_model
        self._fpdb  = FingerprintDB()

    # ------------------------------------------------------------------ #
    def classify(self, text: str = '', subject: str = '',
                 sender: str = '', html_body: str = '',
                 reply_to: str = '') -> dict:
        """
        Run the full 5-layer pipeline and return a structured threat result.

        Parameters
        ----------
        text      : plain-text email body
        subject   : email subject line
        sender    : From header (e.g. "PayPal <noreply@paypa1.com>")
        html_body : raw HTML body (optional)
        reply_to  : Reply-To header (optional)

        Returns
        -------
        dict matching the output schema in the spec
        """
        combined = f"{subject} {text}".strip()

        # --- run all layers ---
        kw_score,     kw_sigs     = _score_keywords(combined)
        html_score,   html_sigs   = _analyze_html(html_body)
        url_score,    url_sigs,   flagged_urls = _analyze_urls(combined, html_body)
        fp_sim,       fp_label    = self._fpdb.check(combined)
        fp_score                  = fp_sim if fp_label else 0.0
        fp_sigs                   = ['CONTENT_FINGERPRINT_MATCH'] if fp_label else []
        sender_score, sender_sigs = _analyze_sender(sender, reply_to)
        ml_score_v,   ml_sigs     = _ml_score(text, self._iso, self._sc, self._rf)

        # --- weighted aggregation ---
        threat_score = min(1.0,
            kw_score     * 0.25 +
            html_score   * 0.15 +
            url_score    * 0.25 +
            fp_score     * 0.20 +
            ml_score_v   * 0.10 +
            sender_score * 0.05
        )

        # --- Keyword confidence fast-path ---
        # When keyword evidence alone is very strong (2+ critical phishing/BEC phrases),
        # the aggregated score is boosted so obvious threats are NEVER labelled SAFE,
        # even if the ML models are unavailable or return low confidence.
        if kw_score >= 0.80:
            threat_score = max(threat_score, 0.72)   # guarantees at least PHISHING
        elif kw_score >= 0.60:
            threat_score = max(threat_score, 0.52)   # guarantees at least SPAM
        elif kw_score >= 0.38:
            threat_score = max(threat_score, 0.32)   # guarantees at least SUSPICIOUS

        threat_score = round(min(1.0, threat_score), 4)

        classification, threat_level, action = _classify(threat_score)

        # deduplicate signals
        all_sigs = kw_sigs + html_sigs + url_sigs + fp_sigs + sender_sigs + ml_sigs
        seen, unique_sigs = set(), []
        for s in all_sigs:
            if s not in seen:
                seen.add(s)
                unique_sigs.append(s)

        return {
            'classification':    classification,
            'legacy_status':     _to_legacy(classification),
            'confidence_score':  threat_score,
            'threat_level':      threat_level,
            'triggered_signals': unique_sigs,
            'flagged_urls':      flagged_urls,
            'flagged_attachments': [],
            'recommended_action': action,
            'explanation':       _build_explanation(
                                     classification, unique_sigs,
                                     flagged_urls, fp_sim),
            'layer_scores': {
                'keyword':      round(kw_score,     3),
                'html':         round(html_score,   3),
                'url':          round(url_score,    3),
                'fingerprint':  round(fp_score,     3),
                'ml_model':     round(ml_score_v,   3),
                'sender':       round(sender_score, 3),
            },
        }

    # ------------------------------------------------------------------ #
    def add_feedback(self, text: str, is_threat: bool,
                     threat_type: str = 'SPAM'):
        """
        Record user feedback to improve fingerprint detection over time.
        Called by POST /api/report-email.
        """
        if is_threat:
            self._fpdb.add(text, threat_type, 'user_reported')
