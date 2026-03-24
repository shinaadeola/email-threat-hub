import os
import re
import numpy as np
import joblib
import warnings
from flask import Flask, request, render_template, redirect, url_for, session, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
import bcrypt
from models_db import db, User, ScanHistory

# Allow OAuth over HTTP for local development only
if os.environ.get('FLASK_ENV') != 'production':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
app.secret_key = 'super_secret_key_for_flask_session_replace_in_prod'

# Configure Database
basedir = os.path.abspath(os.path.dirname(__file__))
database_url = os.environ.get('DATABASE_URL', 'sqlite:///' + os.path.join(basedir, 'database.db'))
# Render provides 'postgres://' but SQLAlchemy requires 'postgresql://'
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create database tables if they don't exist
with app.app_context():
    db.create_all()

# Load models safely on startup
model_path = os.path.join("models", "isoforest.pkl")
scaler_path = os.path.join("models", "scaler.pkl")

iso_model = None
scaler = None

if os.path.exists(model_path) and os.path.exists(scaler_path):
    iso_model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)
else:
    print("Warning: Models not found in models/ directory!")

rf_model_path = os.path.join("models", "random_forest.pkl")
rf_model = None
if os.path.exists(rf_model_path):
    rf_model = joblib.load(rf_model_path)
else:
    print("Warning: Supervised Random Forest model not found!")

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

# --- AUTHENTICATION ROUTES ---

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password').encode('utf-8')
        user = User.query.filter_by(username=username).first()
        stored_hash = user.password if isinstance(user.password, bytes) else user.password.encode('utf-8')
        if user and bcrypt.checkpw(password, stored_hash):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password').encode('utf-8')
        
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists')
            return redirect(url_for('register'))
            
        hashed = bcrypt.hashpw(password, bcrypt.gensalt())
        # Make the first user an admin automatically
        is_admin = User.query.count() == 0
        new_user = User(username=username, password=hashed, is_admin=is_admin)
        db.session.add(new_user)
        db.session.commit()
        
        login_user(new_user)
        return redirect(url_for('dashboard'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- CORE APPLICATION ROUTES ---

@app.route('/dashboard')
@login_required
def dashboard():
    scans = ScanHistory.query.filter_by(user_id=current_user.id).order_by(ScanHistory.timestamp.desc()).limit(10).all()
    return render_template('dashboard.html', scans=scans)

@app.route('/scan', methods=['GET'])
@login_required
def scan_page():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
@login_required
def analyze():
    if iso_model is None or scaler is None or rf_model is None:
        return "System Error: Machine learning models are missing.", 500
        
    email_text = request.form.get('emailInput', '')
    if not email_text.strip():
        return redirect(url_for('scan_page'))
        
    features = extract_custom_features(email_text)
    features_array = np.array(features).reshape(1, -1)
    scaled_features = scaler.transform(features_array)
    iso_score = float(iso_model.decision_function(scaled_features)[0])
    
    stacked_features = np.hstack((features_array[0], [iso_score])).reshape(1, -1)
    rf_prediction = int(rf_model.predict(stacked_features)[0])
    
    if rf_prediction == 1:
        status = "Phishing"
    elif rf_prediction == 2:
        status = "Business Email Compromise"
    else:
        status = "Safe"
    
    # Save to Database
    new_scan = ScanHistory(
        user_id=current_user.id,
        email_subject="Manual Text Scan",
        email_sender="N/A",
        anomaly_score=iso_score,
        status=status
    )
    db.session.add(new_scan)
    db.session.commit()
    
    return render_template('result.html', status=status, score=iso_score)

# --- ADMIN PANEL ---

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        return "Access Denied", 403
    users_count = User.query.count()
    scans_count = ScanHistory.query.count()
    all_scans = ScanHistory.query.order_by(ScanHistory.timestamp.desc()).limit(20).all()
    return render_template('admin.html', users_count=users_count, scans_count=scans_count, scans=all_scans)

# --- GMAIL OAuth 2.0 Integration ---

CLIENT_SECRETS_FILE = "credentials.json"
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

@app.route('/trigger_scan', methods=['POST'])
@login_required
def trigger_scan():
    session['scan_count'] = int(request.form.get('scan_count', 10))
    session['scan_query'] = request.form.get('scan_query', '').strip()
    session['unread_only'] = request.form.get('unread_only') == 'on'
    if request.form.get('switch_account') == 'true':
        session.pop('credentials', None)
    if 'credentials' not in session:
        return redirect(url_for('google_login'))
    return redirect(url_for('scan_inbox'))

@app.route('/google_login')
@login_required
def google_login():
    from google_auth_oauthlib.flow import Flow
    flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES)
    flow.redirect_uri = url_for('oauth2callback', _external=True)
    authorization_url, state = flow.authorization_url(access_type='offline', include_granted_scopes='true', prompt='consent select_account')
    session['state'] = state
    return redirect(authorization_url)

@app.route('/oauth2callback')
@login_required
def oauth2callback():
    from google_auth_oauthlib.flow import Flow
    state = session.get('state')
    if not state:
        return "Error: Missing session state.", 400
    flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
    flow.redirect_uri = url_for('oauth2callback', _external=True)
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials
    session['credentials'] = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes}
    return redirect(url_for('scan_inbox'))

@app.route('/scan_inbox')
@login_required
def scan_inbox():
    if 'credentials' not in session:
        return redirect(url_for('google_login'))
    
    scan_count = session.get('scan_count', 10)
    scan_query = session.get('scan_query', '')
    unread_only = session.get('unread_only', True)
    
    final_query = scan_query
    if unread_only:
        final_query = (final_query + " is:unread").strip()
        
    from google.oauth2.credentials import Credentials
    from gmail_service import fetch_recent_emails
    
    creds = Credentials(**session['credentials'])
    emails = fetch_recent_emails(creds, max_results=scan_count, query=final_query)
    
    if not emails:
        return render_template('inbox_results.html', emails=[])

    scanned_results = []
    
    for email in emails:
        text_content = email['body']
        if not text_content.strip():
             text_content = email['snippet']
             
        features = extract_custom_features(text_content)
        features_array = np.array(features).reshape(1, -1)
        scaled_features = scaler.transform(features_array)
        iso_score = float(iso_model.decision_function(scaled_features)[0])
        
        stacked_features = np.hstack((features_array[0], [iso_score])).reshape(1, -1)
        rf_prediction = int(rf_model.predict(stacked_features)[0])
        
        if rf_prediction == 1:
            status = "Phishing"
        elif rf_prediction == 2:
            status = "Business Email Compromise"
        else:
            status = "Safe"
            
        # Save to Database
        new_scan = ScanHistory(
            user_id=current_user.id,
            email_subject=email['subject'],
            email_sender=email['sender'],
            anomaly_score=iso_score,
            status=status
        )
        db.session.add(new_scan)
        
        scanned_results.append({
            'subject': email['subject'],
            'sender': email['sender'],
            'snippet': email['snippet'],
            'status': status,
            'score': iso_score
        })
        
    db.session.commit()

    return render_template('inbox_results.html', emails=scanned_results)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
