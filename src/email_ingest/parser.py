import os
import email
import re
from email import policy


def clean_text(text):
    """
    Removes sensitive information such as emails and phone numbers.
    Helps meet security and privacy requirements.
    """
    # Remove email addresses
    text = re.sub(r'\S+@\S+', '[EMAIL]', text)

    # Remove phone numbers
    text = re.sub(r'\d{3}[-.\s]?\d{3}[-.\s]?\d{4}', '[PHONE]', text)

    return text


def parse_eml(file_path):
    """
    Parses a .eml file and extracts subject + body text.
    Cleans sensitive data before returning.
    """
    with open(file_path, 'rb') as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    # Extract subject
    subject = msg['subject'] if msg['subject'] else ""

    body = ""

    # Handle multipart emails (text + HTML + attachments)
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    body += part.get_content()
                except:
                    continue
    else:
        # Single-part emails: just grab the content
        body = msg.get_content()

    # Combine subject + body so the model sees all text
    full_text = subject + " " + body

    # Clean sensitive data
    return clean_text(full_text.strip())