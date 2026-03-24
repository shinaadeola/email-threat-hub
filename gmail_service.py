import os
import base64
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import bs4

# If modifying these scopes, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def get_gmail_service():
    """Shows basic usage of the Gmail API.
    Lists the user's Gmail labels.
    """
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            # We are using flow.run_local_server so we don't need a redirect uri specifically, 
            # but we can return the authorization URL for flask to redirect to.
            # Actually, let's use flow.authorization_url() to let flask handle it.
            pass
    
    return creds

def extract_email_body(payload):
    """Recursively extract the plain text body from the email payload."""
    body = ""
    if 'parts' in payload:
        for part in payload['parts']:
            body += extract_email_body(part)
    elif 'body' in payload and 'data' in payload['body']:
        data = payload['body']['data']
        decoded_data = base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
        
        # If it's HTML, we try to extract text or keep HTML for features depending on the need.
        # Since our custom features rely partly on HTML tags, we should return the raw decoded data
        # so `extract_custom_features` can count the HTML tags, URLs, etc.
        body += decoded_data + "\n"
        
    return body

def fetch_recent_emails(creds, max_results=10, query="is:unread", in_folder='inbox'):
    """Fetches the most recent emails using the provided credentials."""
    try:
        # Call the Gmail API
        service = build('gmail', 'v1', credentials=creds)
        
        # Request a list of messages
        results = service.users().messages().list(userId='me', maxResults=max_results, q=query).execute()
        messages = results.get('messages', [])

        # --- FALLBACK MECHANISM ---
        # If the user's inbox is empty for unread emails, fall back to recent emails.
        # Skip this fallback for non-inbox folders like spam/trash.
        skip_fallback = in_folder in ('spam', 'trash', 'sent')
        if not messages and "is:unread" in query and not skip_fallback:
            print("No unread messages found. Falling back to fetching ANY recent messages...")
            fallback_query = query.replace("is:unread", "").strip()
            results = service.users().messages().list(userId='me', maxResults=max_results, q=fallback_query).execute()
            messages = results.get('messages', [])

        email_data = []
        if not messages:
            print('No messages found even with fallback.')
            return email_data

        for message in messages:
            msg = service.users().messages().get(userId='me', id=message['id'], format='full').execute()
            
            # Extract headers (like Subject and From)
            headers = msg['payload'].get('headers', [])
            subject = "No Subject"
            sender = "Unknown Sender"
            
            for header in headers:
                if header['name'] == 'Subject':
                    subject = header['value']
                elif header['name'] == 'From':
                    sender = header['value']
                    
            # Extract body
            body = extract_email_body(msg['payload'])
            
            # Clean up a bit but leave HTML tags for feature extraction
            email_data.append({
                'id': message['id'],
                'sender': sender,
                'subject': subject,
                'body': body,
                'snippet': msg.get('snippet', '')
            })
            
        return email_data

    except Exception as error:
        print(f'An error occurred: {error}')
        return []

