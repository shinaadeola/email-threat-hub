import os
import re
import json
import numpy as np
import joblib
import warnings
from flask import Flask, request, render_template, redirect, url_for, session, flash, jsonify
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
import bcrypt
from models_db import db, User, ScanHistory

# Allow OAuth over HTTP for local development only
if os.environ.get('FLASK_ENV') != 'production':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
app.secret_key = 'super_secret_key_for_flask_session_replace_in_prod'

# Fix url_for generating http:// instead of https:// behind Render's reverse proxy
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

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
    # Safe migration: add new columns to scan_history if they don't exist yet.
    # db.create_all() only creates new tables — it never alters existing ones.
    # This block handles the Render PostgreSQL deployment case.
    try:
        with db.engine.connect() as conn:
            migration_stmts = [
                "ALTER TABLE scan_history ADD COLUMN IF NOT EXISTS threat_classification VARCHAR(20)",
                "ALTER TABLE scan_history ADD COLUMN IF NOT EXISTS confidence_score FLOAT",
                "ALTER TABLE scan_history ADD COLUMN IF NOT EXISTS detection_signals TEXT",
            ]
            for stmt in migration_stmts:
                try:
                    conn.execute(db.text(stmt))
                except Exception:
                    pass  # column may already exist or DB doesn't support IF NOT EXISTS
            conn.commit()
    except Exception as e:
        print(f"Migration warning (non-fatal): {e}")


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

# ---- Instantiate the multi-signal Threat Engine ----
from threat_engine import ThreatEngine
threat_engine = ThreatEngine(iso_model=iso_model, scaler=scaler, rf_model=rf_model)
print("Multi-Signal Threat Engine initialised.")

# extract_custom_features is kept for backward compatibility (used in tests)
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

# (Old keyword lists and keyword_threat_score removed — superseded by ThreatEngine)


# --- AUTHENTICATION ROUTES ---

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/health')
def health():
    return 'OK', 200

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password').encode('utf-8')
        user = User.query.filter_by(username=username).first()
        stored_hash = user.password.encode('utf-8') if isinstance(user.password, str) else user.password
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
            
        hashed = bcrypt.hashpw(password, bcrypt.gensalt()).decode('utf-8')
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
    email_text = request.form.get('emailInput', '')
    if not email_text.strip():
        return redirect(url_for('scan_page'))

    # FIX-5: Parse submitted email text for richer context instead of passing empty strings
    parsed_subject = ''
    parsed_sender = ''
    parsed_html = ''
    parsed_reply_to = ''
    remaining_body = email_text

    lines = email_text.splitlines()
    header_end = 0
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            header_end = i
            break
        lower = stripped.lower()
        if lower.startswith('subject:'):
            parsed_subject = stripped[8:].strip()
        elif lower.startswith('from:'):
            parsed_sender = stripped[5:].strip()
        elif lower.startswith('reply-to:'):
            parsed_reply_to = stripped[9:].strip()

    # Reconstruct body without parsed headers
    if header_end > 0:
        remaining_body = '\n'.join(lines[header_end:]).strip()

    # Detect if body contains HTML
    if re.search(r'<(html|body|div|table|a\s)', remaining_body, re.I):
        parsed_html = remaining_body

    # Run the full multi-signal engine with parsed context
    result = threat_engine.classify(
        text=remaining_body or email_text,
        subject=parsed_subject,
        sender=parsed_sender,
        html_body=parsed_html,
        reply_to=parsed_reply_to
    )

    # Feature display (for the Structural Features panel)
    feature_names = [
        'Text Length', 'HTML Tags', 'URLs', 'Exclamation Marks', 'Dollar Signs',
        'Uppercase Ratio', 'Urgent Words', 'Account Words', 'Digit Count',
        'Lexical Diversity', 'Login Words', 'Reward Words', 'URL Shorteners',
        'Excessive Punctuation', 'Avg Word Length'
    ]
    raw_features = extract_custom_features(email_text)
    features_display = [{'name': n, 'value': round(v, 4)}
                        for n, v in zip(feature_names, raw_features)]

    # Persist to DB
    new_scan = ScanHistory(
        user_id=current_user.id,
        email_subject='Manual Text Scan',
        email_sender='N/A',
        anomaly_score=result['layer_scores']['ml_model'],
        status=result['legacy_status'],
        threat_classification=result['classification'],
        confidence_score=result['confidence_score'],
        detection_signals=json.dumps(result['triggered_signals'][:10])
    )
    db.session.add(new_scan)
    db.session.commit()

    return render_template(
        'result.html',
        result=result,
        features=features_display,
        # legacy shims so existing template refs still work
        status=result['legacy_status'],
        score=result['layer_scores']['ml_model'],
    )

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

# Gmail category label mapping
GMAIL_CATEGORIES = {
    'inbox':      '',                         # default, no extra label
    'important':  'label:important',
    'spam':       'in:spam',
    'trash':      'in:trash',
    'starred':    'is:starred',
    'sent':       'in:sent',
    'social':     'category:social',
    'promotions': 'category:promotions',
    'updates':    'category:updates',
    'forums':     'category:forums',
    'purchases':  'category:purchases',
}

@app.route('/trigger_scan', methods=['POST'])
@login_required
def trigger_scan():
    session['scan_count'] = int(request.form.get('scan_count', 10))
    session['scan_query'] = request.form.get('scan_query', '').strip()
    session['unread_only'] = request.form.get('unread_only') == 'on'
    session['gmail_category'] = request.form.get('gmail_category', 'inbox')
    if request.form.get('switch_account') == 'true':
        session.pop('credentials', None)
    if 'credentials' not in session:
        return redirect(url_for('google_login'))
    return redirect(url_for('scan_inbox'))

@app.route('/google_login')
@login_required
def google_login():
    try:
        from google_auth_oauthlib.flow import Flow
        flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES)
        flow.redirect_uri = url_for('oauth2callback', _external=True)
        authorization_url, state = flow.authorization_url(access_type='offline', include_granted_scopes='true', prompt='consent select_account')
        session['state'] = state
        return redirect(authorization_url)
    except Exception as e:
        print(f'Google login error: {e}')
        flash(f'Could not connect to Google: {e}')
        return redirect(url_for('dashboard'))

@app.route('/oauth2callback')
@login_required
def oauth2callback():
    try:
        from google_auth_oauthlib.flow import Flow
        state = session.get('state')
        if not state:
            flash('OAuth session expired. Please try again.')
            return redirect(url_for('dashboard'))
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
            'scopes': list(credentials.scopes) if credentials.scopes else []}
        return redirect(url_for('scan_inbox'))
    except Exception as e:
        print(f'OAuth callback error: {e}')
        flash(f'Gmail authentication failed: {e}')
        return redirect(url_for('dashboard'))

@app.route('/scan_inbox')
@login_required
def scan_inbox():
    if 'credentials' not in session:
        return redirect(url_for('google_login'))

    scan_count    = session.get('scan_count', 10)
    scan_query    = session.get('scan_query', '')
    unread_only   = session.get('unread_only', True)
    gmail_category = session.get('gmail_category', 'inbox')

    try:
        category_filter = GMAIL_CATEGORIES.get(gmail_category, '')
        final_query = ' '.join(filter(None, [category_filter, scan_query]))
        skip_unread = gmail_category in ('spam', 'trash', 'sent')
        if unread_only and not skip_unread:
            final_query = (final_query + ' is:unread').strip()

        from google.oauth2.credentials import Credentials
        from gmail_service import fetch_recent_emails

        creds  = Credentials(**session['credentials'])
        emails = fetch_recent_emails(creds, max_results=scan_count,
                                     query=final_query, in_folder=gmail_category)

        if not emails:
            return render_template('inbox_results.html', emails=[],
                                   scanned_folder=gmail_category.capitalize())

        scanned_results = []
        for email in emails:
            text_content = email['body'] or email['snippet']

            result = threat_engine.classify(
                text=text_content,
                subject=email.get('subject', ''),
                sender=email.get('sender', ''),
                html_body='',
                reply_to=''
            )

            new_scan = ScanHistory(
                user_id=current_user.id,
                email_subject=email['subject'],
                email_sender=email['sender'],
                anomaly_score=result['layer_scores']['ml_model'],
                status=result['legacy_status'],
                threat_classification=result['classification'],
                confidence_score=result['confidence_score'],
                detection_signals=json.dumps(result['triggered_signals'][:10])
            )
            db.session.add(new_scan)

            scanned_results.append({
                'subject':        email['subject'],
                'sender':         email['sender'],
                'snippet':        email['snippet'],
                'status':         result['legacy_status'],
                'classification': result['classification'],
                'confidence':     result['confidence_score'],
                'threat_level':   result['threat_level'],
                'score':          result['layer_scores']['ml_model'],
                'signals':        result['triggered_signals'][:5],
            })

        db.session.commit()
        return render_template('inbox_results.html', emails=scanned_results,
                               scanned_folder=gmail_category.capitalize())

    except Exception as e:
        print(f'Gmail scan error: {e}')
        # Clear bad credentials so the user can re-authenticate
        session.pop('credentials', None)
        flash(f'Gmail scan failed: {e}. Please try connecting again.')
        return redirect(url_for('dashboard'))


# =============================================================================
# REST API — POST /api/classify-email
# =============================================================================

@app.route('/api/classify-email', methods=['POST'])
@login_required
def api_classify_email():
    """
    Accepts JSON: {subject, from, reply_to, body_text, body_html}
    Returns structured threat classification result.
    """
    data      = request.get_json(force=True, silent=True) or {}
    body_text = data.get('body_text', '') or data.get('body', '')
    subject   = data.get('subject', '')
    sender    = data.get('from', '') or data.get('sender', '')
    reply_to  = data.get('reply_to', '')
    html_body = data.get('body_html', '')

    if not body_text.strip() and not subject.strip():
        return jsonify({'error': 'body_text or subject is required'}), 400

    result = threat_engine.classify(
        text=body_text,
        subject=subject,
        sender=sender,
        html_body=html_body,
        reply_to=reply_to
    )

    # Optionally persist to DB
    new_scan = ScanHistory(
        user_id=current_user.id,
        email_subject=subject or 'API Scan',
        email_sender=sender or 'N/A',
        anomaly_score=result['layer_scores']['ml_model'],
        status=result['legacy_status'],
        threat_classification=result['classification'],
        confidence_score=result['confidence_score'],
        detection_signals=json.dumps(result['triggered_signals'][:10])
    )
    db.session.add(new_scan)
    db.session.commit()

    return jsonify(result)


# =============================================================================
# REST API — POST /api/report-email  (feedback loop)
# =============================================================================

@app.route('/api/report-email', methods=['POST'])
@login_required
def api_report_email():
    """
    Feedback endpoint: marks an email as a FP/FN and updates the fingerprint DB.
    Accepts JSON: {body_text, is_threat (bool), threat_type (SPAM|PHISHING|BEC)}
    """
    data       = request.get_json(force=True, silent=True) or {}
    body_text  = data.get('body_text', '')
    is_threat  = bool(data.get('is_threat', False))
    threat_type = data.get('threat_type', 'SPAM').upper()

    if not body_text.strip():
        return jsonify({'error': 'body_text is required'}), 400

    threat_engine.add_feedback(body_text, is_threat, threat_type)
    return jsonify({'status': 'ok', 'recorded': True,
                    'fingerprint_added': is_threat})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
