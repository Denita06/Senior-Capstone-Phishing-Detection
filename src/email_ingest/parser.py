import os
import email
from email import policy


def parse_eml(file_path):
    # Open the email file in binary mode
    with open(file_path, 'rb') as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    # Get the email subject (use empty string if missing)
    subject = msg['subject'] if msg['subject'] else ""

    body = ""
    # Emails can be multipart (text + HTML + attachments)
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body += part.get_content()
    else:
        # Single-part emails: just grab the content
        body = msg.get_content()

    # Combine subject + body so the model sees all text
    return subject + " " + body