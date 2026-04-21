from googleapiclient.discovery import build
import base64
import re
from bs4 import BeautifulSoup

def get_latest_emails(creds, max_results=10, label="INBOX"):
    service = build('gmail', 'v1', credentials=creds)

    results = service.users().messages().list(
        userId='me',
        labelIds=[label],
        maxResults=max_results
    ).execute()

    messages = results.get('messages', [])
    email_data = []

    for msg in messages:
        m = service.users().messages().get(
            userId='me', id=msg['id'], format='full'
        ).execute()

        headers = m.get('payload', {}).get('headers', [])

        subject = next((h['value'] for h in headers if h['name'] == 'Subject'), "")
        # Keep the full raw sender string for spoofing detection
        sender_raw = next((h['value'] for h in headers if h['name'] == 'From'), "")
        # Capture Reply-To for mismatch analysis
        reply_to = next((h['value'] for h in headers if h['name'] == 'Reply-To'), "")

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
    try:
        payload = message.get('payload', {})
        def extract_text(parts):
            for part in parts:
                mime = part.get('mimeType', "")
                if mime == 'text/plain':
                    data = part['body'].get('data')
                    if data: return base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
                elif mime == 'text/html':
                    data = part['body'].get('data')
                    if data:
                        html = base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
                        return get_cleaned_text(html)
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
    soup = BeautifulSoup(raw_html, "html.parser")
    for tag in soup(["script", "style"]):
        tag.decompose()
    return " ".join(soup.get_text().split())