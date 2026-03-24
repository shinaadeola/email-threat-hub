import os
import email
from email.policy import default
import numpy as np
import pandas as pd
import joblib

from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, accuracy_score, f1_score
from sklearn.preprocessing import StandardScaler
import re

# Use relative paths for deployment
BASE_DATA_DIR = os.path.join("data", "spamassassin")
HAM_DIR = os.path.join(BASE_DATA_DIR, "easy_ham", "easy_ham")
SPAM_DIR = os.path.join(BASE_DATA_DIR, "spam_2", "spam_2")

def extract_email_text(file_path):
    """Extract subject and body from a raw email file."""
    try:
        with open(file_path, "rb") as f:
            msg = email.message_from_binary_file(f, policy=default)
        
        subject = msg.get("Subject", "")
        body = ""
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain":
                    try:
                        body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    except:
                        pass
        else:
            try:
                body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
            except:
                pass
                
        return str(subject) + " " + body
    except Exception as e:
        return ""

def load_data(directory, label, max_files=None):
    """Load emails from a directory, skip subdirectories, and assign a label."""
    data = []
    labels = []
    
    if not os.path.exists(directory):
        print(f"Warning: Directory not found - {directory}")
        return data, labels
        
    filenames = os.listdir(directory)
    if max_files:
        filenames = filenames[:max_files]
        
    for filename in filenames:
        path = os.path.join(directory, filename)
        if os.path.isfile(path): # Skip directories like __MACOSX
            text = extract_email_text(path)
            if text.strip():
                data.append(text)
                labels.append(label)
    return data, labels

def extract_custom_features(text):
    """
    Extracts custom metadata clues (features) from an email text to help 
    the model identify suspicious patterns that go beyond mere word counts.
    """
    if not isinstance(text, str):
        text = str(text)
        
    # 1. Total Character Length
    length = len(text)
    
    # 2. Number of HTML tags (Scammers often rely on raw HTML)
    html_tags = len(re.findall(r'<[^>]+>', text))
    
    # 3. Number of URLs (Phishing heavily relies on links)
    urls = len(re.findall(r'(http[s]?://|www\.)', text.lower()))
    
    # 4. Count of suspicious characters often used in scams
    exclamations = text.count('!')
    dollar_signs = text.count('$')
    
    # 5. ALL CAPS ratio (Scammers like shouting to create urgency)
    uppers = sum(1 for c in text if c.isupper())
    upper_ratio = uppers / length if length > 0 else 0
    
    # 6. Count of specific scam trigger words
    text_lower = text.lower()
    urgent_words = text_lower.count('urgent') + text_lower.count('immediate') + text_lower.count('action required')
    account_words = text_lower.count('account') + text_lower.count('suspend') + text_lower.count('verify')
    
    # 7. Total Number of Digits
    num_digits = sum(1 for c in text if c.isdigit())
    
    # 8. Lexical Diversity
    words = re.findall(r'\b\w+\b', text_lower)
    lexical_diversity = len(set(words)) / len(words) if len(words) > 0 else 0
    
    # 9. Count of Login/Security words
    login_words = text_lower.count('password') + text_lower.count('login') + text_lower.count('secure') + text_lower.count('locked')
    
    # 10. Default Scam/Reward words
    reward_words = text_lower.count('free') + text_lower.count('prize') + text_lower.count('guaranteed') + text_lower.count('winner')
    
    # 11. URL Shorteners
    shorteners = len(re.findall(r'(bit\.ly|tinyurl\.com|goo\.gl|ow\.ly|is\.gd|tiny\.cc)', text_lower))
    
    # 12. Excessive/Aggressive punctuation
    excessive_punctuation = len(re.findall(r'[\?\*\#\@]{2,}', text))
    
    # 13. Average Word Length
    avg_word_length = sum(len(w) for w in words) / len(words) if len(words) > 0 else 0
    
    return [
        length, html_tags, urls, exclamations, dollar_signs, upper_ratio, 
        urgent_words, account_words, num_digits, lexical_diversity, 
        login_words, reward_words, shorteners, excessive_punctuation, avg_word_length
    ]

def main():
    print("Loading datasets...")
    # Load Ham (Normal) from SpamAssassin
    ham_texts, ham_labels = load_data(HAM_DIR, label=1) # 1 = Inlier (Normal/Ham)
    print(f"Loaded {len(ham_texts)} normal (Ham) emails from SpamAssassin.")
    
    # Load Spam (Anomaly/Threat) from SpamAssassin
    spam_texts, spam_labels = load_data(SPAM_DIR, label=-1) # -1 = Outlier (Anomaly/Spam)
    print(f"Loaded {len(spam_texts)} threat (Spam) emails from SpamAssassin.")
    
    if not ham_texts:
        print("Error: No Ham emails loaded. Exiting.")
        return

    # Let's split Ham into Train and Test
    # 80% for training the normal profile, 20% for testing
    from sklearn.model_selection import train_test_split
    ham_train, ham_test, _, _ = train_test_split(ham_texts, ham_labels, test_size=0.2, random_state=42)
    
    # Our test set will consist of the unseen Ham + ALL the Spam
    X_test_text = list(ham_test) + spam_texts
    y_test = [1]*len(list(ham_test)) + [-1]*len(spam_texts)
    
    print(f"\nTraining set size (Normal Only): {len(ham_train)}")
    print(f"Testing set size (Normal + Threats): {len(X_test_text)}")

    print("\nExtracting Custom Engineering Features (URLs, HTML, Suspicious patterns)...")
    # Extract structural clues ONLY (Drop TF-IDF)
    X_train_custom = np.array([extract_custom_features(text) for text in ham_train])
    X_test_custom = np.array([extract_custom_features(text) for text in X_test_text])
    
    # Scale custom features so they are treated equally
    scaler = StandardScaler()
    X_train_features = scaler.fit_transform(X_train_custom)
    X_test_features = scaler.transform(X_test_custom)

    print("\nTraining Isolation Forest Model on Normal Data...")
    # Using fixed contamination as recommended for simplicity and defensibility
    contamination_val = 0.1
    model = IsolationForest(contamination=contamination_val, random_state=42, n_estimators=100)
    
    # Train the model using strictly the 8 Cybersecurity Features
    model.fit(X_train_features)

    print("\nEvaluating Model on Test Data...")
    y_pred = model.predict(X_test_features)
    
    print("\n--- Final Results ---")
    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, pos_label=-1)
    print(f"Final Accuracy: {acc:.4f}")
    print(f"Final F1-Score (Anomaly): {f1:.4f}")
    
    # Map -1 to 'Threat' and 1 to 'Safe' for clear reporting
    target_names = ['Threat/Anomaly (-1)', 'Safe/Ham (1)']
    print(classification_report(y_test, y_pred, target_names=target_names))

    print("\nSaving model and scaler for deployment...")
    os.makedirs("models", exist_ok=True)
    joblib.dump(model, "models/isoforest.pkl")
    joblib.dump(scaler, "models/scaler.pkl")
    print("Saved to models/isoforest.pkl and models/scaler.pkl")

if __name__ == "__main__":
    main()
