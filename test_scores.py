import joblib, numpy as np, re
iso_model = joblib.load('models/isoforest.pkl')
scaler = joblib.load('models/scaler.pkl')

def extract(text):
    length = len(text)
    html_tags = len(re.findall(r'<[^>]+>', text))
    urls = len(re.findall(r'(http[s]?://|www\.)', text.lower()))
    exclamations = text.count('!')
    dollar_signs = text.count('$')
    uppers = sum(1 for c in text if c.isupper())
    upper_ratio = uppers / length if length > 0 else 0
    text_lower = text.lower()
    urgent_words = text_lower.count('urgent') + text_lower.count('immediate') + text_lower.count('action required')
    account_words = text_lower.count('account') + text_lower.count('suspend') + text_lower.count('verify')
    return [length, html_tags, urls, exclamations, dollar_signs, upper_ratio, urgent_words, account_words]

s1 = 'Hello, how are you? I hope you are having a wonderful day. Please find the attached report.'
s2 = 'URGENT!!! Verify your BANK account immediately at http://scam.com $$$ <script>alert(1);</script>'

print('S1 score:', iso_model.decision_function(scaler.transform([extract(s1)]))[0])
print('S2 score:', iso_model.decision_function(scaler.transform([extract(s2)]))[0])
