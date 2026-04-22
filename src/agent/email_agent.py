from googleapiclient.discovery import build
import base64
import re
from bs4 import BeautifulSoup

def get_latest_emails(creds, max_results=10, label="INBOX"):
    """
    Connects to Gmail API and fetches the most recent emails.
    Extracts headers like Subject, Sender, and Reply-To for phishing analysis.
    """
    service = build('gmail', 'v1', credentials=creds)

    # Request a list of message IDs from the specified label (e.g., INBOX or SPAM)
    results = service.users().messages().list(
        userId='me',
        labelIds=[label],
        maxResults=max_results
    ).execute()

    messages = results.get('messages', [])
    email_data = []

    for msg in messages:
        # Fetch the full content of each specific email ID
        m = service.users().messages().get(
            userId='me', id=msg['id'], format='full'
        ).execute()

        headers = m.get('payload', {}).get('headers', [])

        # Parse specific headers needed for security auditing
        subject = next((h['value'] for h in headers if h['name'] == 'Subject'), "")
        # Keep the full raw sender string for spoofing detection
        sender_raw = next((h['value'] for h in headers if h['name'] == 'From'), "")
        # Capture Reply-To for mismatch analysis
        reply_to = next((h['value'] for h in headers if h['name'] == 'Reply-To'), "")

        # Extract the actual text/content of the email
        body = get_full_email_body(m)

        email_data.append({
            'id': msg['id'],
            'subject': subject,
            'sender': sender_raw,
            'reply_to': reply_to,
            'body': body,
            'source': label
        })

    return email_data

def get_full_email_body(message):
    """
    Recursively decodes the email body from base64. 
    Handles multi-part emails (Plain text vs HTML) and returns the most readable version.
    """
    try:
        payload = message.get('payload', {})
        def extract_text(parts):
            for part in parts:
                mime = part.get('mimeType', "")
                # Prioritize plain text for analysis
                if mime == 'text/plain':
                    data = part['body'].get('data')
                    if data: return base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
                # Fallback to HTML if plain text isn't available
                elif mime == 'text/html':
                    data = part['body'].get('data')
                    if data:
                        html = base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
                        return get_cleaned_text(html)
                # Recursively look deeper if the email has nested parts (common in complex emails) 
                if 'parts' in part:
                    result = extract_text(part['parts'])
                    if result: return result
            return ""

        if 'parts' in payload:
            body = extract_text(payload['parts'])
        else:
            data = payload.get('body', {}).get('data')
            body = base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore') if data else ""
        return body if body else message.get('snippet', "")
    except Exception as e:
        return ""
    
def get_cleaned_text(raw_html):
    """
    Uses BeautifulSoup to strip HTML tags and scripts, 
    leaving only the visible text for the ML model to analyze.
    """
    soup = BeautifulSoup(raw_html, "html.parser")
    for tag in soup(["script", "style"]):
        tag.decompose()
    return " ".join(soup.get_text().split())