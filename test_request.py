import urllib.request
import urllib.parse
import re

# Simulate the user ONLY pasting the link
payload = 'http://scam.com'

data = urllib.parse.urlencode({'emailInput': payload}).encode('utf-8')
req = urllib.request.Request('http://localhost:5000/analyze', data=data)
try:
    response = urllib.request.urlopen(req)
    html = response.read().decode('utf-8')
    
    score_match = re.search(r'<span class="metric-value">(.*?)</span>', html)
    if score_match:
        print("Score rendered on page for JUST the link:", score_match.group(1))
    
    features = re.findall(r'<td class="text-right font-mono">(.*?)</td>', html)
    print("Features extracted by Flask app:", features)
    
except Exception as e:
    print(f"Error: {e}")
