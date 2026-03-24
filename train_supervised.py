"""
train_supervised.py

Trains a Stacked Supervised Machine Learning model (Random Forest) for 
Email Threat Detection. It uses a 15-Feature Extractor and the an Anomaly Score
from the previously trained Isolation Forest.
"""

import re
import joblib
import numpy as np
import pandas as pd
from datasets import load_dataset
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, precision_score, recall_score, f1_score

def extract_custom_features(text):
    if not isinstance(text, str):
        text = str(text)
        
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
    
    num_digits = sum(1 for c in text if c.isdigit())
    
    words = re.findall(r'\b\w+\b', text_lower)
    lexical_diversity = len(set(words)) / len(words) if len(words) > 0 else 0
    
    login_words = text_lower.count('password') + text_lower.count('login') + text_lower.count('secure') + text_lower.count('locked')
    reward_words = text_lower.count('free') + text_lower.count('prize') + text_lower.count('guaranteed') + text_lower.count('winner')
    
    shorteners = len(re.findall(r'(bit\.ly|tinyurl\.com|goo\.gl|ow\.ly|is\.gd|tiny\.cc)', text_lower))
    excessive_punctuation = len(re.findall(r'[\?\*\#\@]{2,}', text))
    avg_word_length = sum(len(w) for w in words) / len(words) if len(words) > 0 else 0
    
    return [
        length, html_tags, urls, exclamations, dollar_signs, upper_ratio, 
        urgent_words, account_words, num_digits, lexical_diversity, 
        login_words, reward_words, shorteners, excessive_punctuation, avg_word_length
    ]

def main():
    print("Loading Hugging Face Dataset: zefang-liu/phishing-email-dataset...")
    # Load the phishing dataset
    dataset = load_dataset("zefang-liu/phishing-email-dataset")
    df = dataset['train'].to_pandas()
    
    # The zefang-liu dataset uses 'Email Text' and 'Email Type'
    if 'Email Text' not in df.columns or 'Email Type' not in df.columns:
        print(f"Error: Expected 'Email Text' and 'Email Type' columns, got {df.columns}. Exiting.")
        return
        
    print(f"Loaded {len(df)} emails (Benign and Phishing) successfully.")
    
    # Drop any nulls
    df = df.dropna(subset=['Email Text', 'Email Type'])
    
    X_raw = df['Email Text'].astype(str).tolist()
    
    # Extract labels. 'Phishing Email' -> 1, 'Safe Email' -> 0
    y = [1 if 'Phishing' in str(label) else 0 for label in df['Email Type']]
    
    # --- ADDING THE NEW CATEGORY (BUSINESS EMAIL COMPROMISE - BEC) ---
    print("\nAdding the NEW unseen category: Business Email Compromise (BEC)...")
    bec_emails = [
        "URGENT: Please wire $50,000 to the attached vendor account immediately. The CEO needs this finalized today.",
        "Are you at your desk? I need you to purchase 10 Apple gift cards for a client presentation. Don't call me, I'm in a meeting.",
        "Please update my direct deposit information for this upcoming payroll cycle to the attached routing number.",
        "Confidential: We are acquiring a new company. Send the requested funds to the escrow account ASAP.",
        "Invoice Overdue. Please process the attached invoice #88921 to avoid service suspension. - CFO",
        "Hi, I'm locked out of my account. Can you reset my password and send it to my personal email? Thanks.",
        "Urgent request from the Executive team: Complete the wire transfer of $100K by 2PM today.",
        "Immediate Action Required: Vendor payment failed. Please use these new bank details to complete the transfer.",
        "I need you to handle a highly confidential financial transaction for me. Reply when you get this. - CEO",
        "Please change my payroll direct deposit to my new bank account at Wells Fargo. Attached is the voided check."
    ] * 20 # Duplicate them to create a solid class weight (200 samples)
    
    X_raw.extend(bec_emails)
    y.extend([2] * len(bec_emails)) # Label 2 represents BEC
    
    print(f"Total Emails after adding BEC: {len(X_raw)}")
    
    print("\nPhase 1: Extracting 15 Custom Features for all emails...")
    X_features = np.array([extract_custom_features(text) for text in X_raw])
    
    print("Phase 2: Generating Anomaly Scores from the Isolation Forest...")
    iso_model = joblib.load("models/isoforest.pkl")
    scaler = joblib.load("models/scaler.pkl")
    
    # Scale Features for the Isolation Forest
    X_scaled_for_iso = scaler.transform(X_features)
    
    # Get the continuous anomaly score (lower is more anomalous)
    anomaly_scores = iso_model.decision_function(X_scaled_for_iso)
    
    # Phase 3: Stack features together (15 Original + 1 Anomaly Score)
    X_stacked = np.hstack((X_features, anomaly_scores.reshape(-1, 1)))
    
    # Split into Train and Test (80/20)
    print("\nSplitting data into 80% Training and 20% Testing Validation...")
    X_train, X_test, y_train, y_test = train_test_split(X_stacked, y, test_size=0.2, random_state=42)
    
    print("Phase 4: Training the State-of-the-Art Random Forest Classifier...")
    # 100 decision trees
    rf_model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rf_model.fit(X_train, y_train)
    
    print("\nEvaluating Supervised Model Accuracy on Unseen Test Data...")
    y_pred = rf_model.predict(X_test)
    
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    
    print("-" * 40)
    print(f"Accuracy:  {acc * 100:.2f}%")
    print(f"Precision: {prec * 100:.2f}%")
    print(f"Recall:    {rec * 100:.2f}%")
    print(f"F1-Score:  {f1 * 100:.2f}%")
    print("-" * 40)
    
    target_names = ['Safe (0)', 'Phishing (1)', 'Business Email Compromise (2)']
    print(classification_report(y_test, y_pred, target_names=target_names))
    
    print("\nSaving the Ultimate Supervised Brain...")
    joblib.dump(rf_model, "models/random_forest.pkl")
    print("Saved -> models/random_forest.pkl")
    
if __name__ == "__main__":
    main()
