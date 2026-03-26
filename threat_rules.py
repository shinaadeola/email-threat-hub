"""
threat_rules.py
===============
Extended rule definitions for the Email Threat Engine.
Imported by threat_engine.py to supplement its base rule sets.
Kept in a separate file so the core engine is never corrupted by edits here.
"""

# ── Extra SPAM phrases (supplement SPAM_WEIGHTED in threat_engine.py) ─────────
SPAM_EXTRA = {
    # Advance-fee / 419 fraud
    'dear beneficiary':                     0.92,
    'transfer of funds':                    0.88,
    'transfer of money':                    0.85,
    'fund transfer':                        0.82,
    'unclaimed money':                      0.82,
    'inheritance money':                    0.82,
    'next of kin':                          0.85,
    'foreign funds':                        0.82,
    'million usd':                          0.80,
    'percentage for your assistance':       0.88,
    'percent of the total sum':             0.88,
    'attorney to a late client':            0.90,
    'died intestate':                       0.90,
    'modalities for the transfer':          0.88,
    'diplomatic agent':                     0.78,
    # Lottery / prize
    'claim your reward':                    0.85,
    'lottery draw':                         0.80,
    'you have been selected as a winner':   0.88,
    'selected for a prize':                 0.82,
    'grand prize winner':                   0.88,
    'prize notification':                   0.82,
    'winning notification':                 0.82,
    # Pharmaceutical
    'erectile dysfunction':                 0.75,
    'lose weight fast':                     0.70,
    'burn fat fast':                        0.68,
    # Adult / dating
    'local singles':                        0.78,
    'sex tonight':                          0.92,
    'naked pictures':                       0.92,
    'secret admirers':                      0.78,
    # Financial spam
    'earn money online':                    0.68,
    'passive income':                       0.52,
    'financial freedom':                    0.52,
    'guaranteed approval':                  0.65,
    'cash advance':                         0.62,
    'payday loan':                          0.68,
    'debt relief':                          0.58,
    # Employment / job scam
    'mystery shopper':                      0.78,
    'work as our agent':                    0.82,
    'payment processing agent':             0.85,
    'reshipping agent':                     0.85,
    'package forwarding':                   0.72,
    'no experience needed':                 0.55,
    'earn 500 dollars per day':             0.80,
    'earn 1000 dollars per day':            0.82,
    'unlimited earning potential':          0.70,
    # Generic
    'you have been specially selected':     0.78,
    'dear valued customer':                 0.55,
    'dear account holder':                  0.62,
    'dear friend':                          0.48,
    'dear sir/madam':                       0.52,
}

# ── Extra PHISHING phrases ─────────────────────────────────────────────────────
PHISHING_EXTRA = {
    # Additional account threats
    'your account has been limited':            0.90,
    'your account has been compromised':        0.90,
    'click here to restore your account':       0.90,
    'restore account access':                   0.88,
    # Brand impersonation extras
    'apple id verification':                    0.88,
    'google account has been locked':           0.90,
    'paypal account suspended':                 0.92,
    'microsoft account is locked':              0.92,
    'outlook account suspended':                0.90,
    'amazon account locked':                    0.90,
    'amazon account has been suspended':        0.92,
    'netflix account on hold':                  0.88,
    'bank account suspended':                   0.90,
    # Credential harvesting extras
    'update your payment method':               0.88,
    'update your credit card':                  0.88,
    'your payment information is outdated':     0.88,
    'your password needs to be updated':        0.85,
    'confirm your identity':                    0.72,
    'confirm your email address':               0.72,
    'verify your email':                        0.68,
    # OTP / MFA phishing
    'enter your one-time code':                 0.85,
    'enter the verification code':              0.80,
    'your verification code is':                0.72,
    'authentication code':                      0.65,
    # Government / tax
    'tax authority':                            0.72,
    'stimulus check':                           0.78,
    'government grant':                         0.80,
    'unclaimed tax refund':                     0.88,
    'irs requires':                             0.85,
    # Suspicious activity extras
    'unusual sign-in':                          0.82,
    'unauthorized access':                      0.78,
    # URL / urgency
    'click the button below':                   0.60,
    'tap the link below':                       0.62,
    'click here to avoid':                      0.78,
    'click here or your account':               0.88,
    'permanent suspension':                     0.82,
    'temporary suspension':                     0.78,
    'account will be deleted':                  0.82,
    'account deletion in':                      0.85,
    'immediate action required':                0.78,
    'urgent action required':                   0.82,
}

# ── Extra BEC phrases ──────────────────────────────────────────────────────────
BEC_EXTRA = {
    'initiate a transfer':              0.82,
    'bank transfer':                    0.78,
    'international transfer':           0.72,
    'transfer to a new account':        0.85,
    'updated bank account':             0.88,
    'routing number':                   0.65,
    'buy gift cards':                   0.90,
    'i need gift cards':                0.88,
    'send me the codes':                0.88,
    'scratch the back':                 0.82,
    'gift card codes':                  0.85,
    'keep this confidential':           0.82,
    'this is time sensitive':           0.72,
    'company acquisition':              0.72,
    'approved by the cfo':              0.85,
    'approved by management':           0.72,
    'invoice attached':                 0.45,
    'overdue invoice':                  0.65,
    'urgent payment':                   0.72,
    'outstanding balance':              0.55,
    'final demand':                     0.65,
}

# ── Negative rules — legitimate signals that REDUCE the threat score ───────────
# Applied AFTER positive scoring as a deduction.  Max deduction capped so that
# genuinely malicious emails can't escape detection via legitimate-looking footers.
NEGATIVE_RULES = {
    'unsubscribe':                              -0.30,
    'to unsubscribe from':                      -0.40,
    'view this email in your browser':          -0.35,
    'if you no longer wish to receive':         -0.40,
    'you are receiving this email because':     -0.35,
    'this email was sent to':                   -0.30,
    'privacy policy':                           -0.25,
    'terms of service':                         -0.25,
    'terms and conditions':                     -0.25,
    'our mailing address':                      -0.40,
    '\u00a9':                                   -0.20,   # © symbol
    'all rights reserved':                      -0.20,
    'sent by':                                  -0.15,
    'powered by':                               -0.15,
    'confidentiality notice':                   -0.20,
    'this message is intended for':             -0.25,
    'if you have received this in error':       -0.30,
    'do not reply to this email':               -0.20,
    'tracking number':                          -0.20,
    'order number':                             -0.20,
    'order confirmation':                       -0.30,
    'your receipt':                             -0.20,
    'invoice number':                           -0.15,
    'account statement':                        -0.15,
    'meeting invitation':                       -0.25,
    'calendar invite':                          -0.25,
    'kind regards':                             -0.15,
    'best regards':                             -0.15,
    'thank you for your purchase':              -0.30,
    'thank you for your order':                 -0.30,
    'your subscription':                        -0.15,
}

# ── Additional obfuscation patterns ───────────────────────────────────────────
EXTRA_OBFUSCATION = [
    # Paypal l33t
    (r'p[a4@][y]?p[a4@][l1|!]', 0.85),
    # G00gle / G0ogle
    (r'g[o0][o0]g[l1][e3]', 0.78),
    # @mazon / 4mazon
    (r'[@4a][mn][a4@][z2][o0]n', 0.78),
    # M1cr0soft
    (r'm[i1]cr[o0]s[o0]ft', 0.78),
]
