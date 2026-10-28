from __future__ import print_function
import base64
from email.mime.text import MIMEText
from email.utils import parseaddr
import os
import pickle

from flask import Flask, jsonify, request
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

SCOPES = ['https://www.googleapis.com/auth/gmail.send']
SENDER_EMAIL = "nicolas.ramirez55243@ucaldas.edu.co"
DEFAULT_SUBJECT = "Correo enviado desde API"
CREDENTIALS_DIR = os.path.join(os.path.dirname(__file__), 'credentials')
CLIENT_SECRET_FILE = os.path.join(CREDENTIALS_DIR, 'credentials.json')
TOKEN_FILE = os.path.join(CREDENTIALS_DIR, 'token.pickle')
app = Flask(__name__)

def authenticate_gmail():
    creds = None
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, 'rb') as token:
            creds = pickle.load(token)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(CLIENT_SECRET_FILE, SCOPES)
            creds = flow.run_local_server(port=0)
        os.makedirs(CREDENTIALS_DIR, exist_ok=True)
        with open(TOKEN_FILE, 'wb') as token:
            pickle.dump(creds, token)
    return creds

def create_message_html(sender, to, subject, html_content):
    message = MIMEText(html_content, "html")  # 👈 Tipo HTML
    message['to'] = to
    message['from'] = sender
    message['subject'] = subject
    raw_message = base64.urlsafe_b64encode(message.as_bytes())
    return {'raw': raw_message.decode()}

def send_message(service, user_id, message):
    sent_message = service.users().messages().send(
        userId=user_id, body=message
    ).execute()
    print(f"✅ Mensaje enviado. ID: {sent_message['id']}")
    return sent_message


def is_valid_email(value):
    name, address = parseaddr(value)
    return bool(name == '' and address == value and '@' in address)


@app.post('/send-email')
def send_email():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="El body debe ser un JSON válido."), 400

    recipient = data.get('to')
    text = data.get('text')
    if not isinstance(recipient, str) or not recipient.strip():
        return jsonify(error="El campo 'to' es obligatorio."), 400
    if not is_valid_email(recipient.strip()):
        return jsonify(error="El campo 'to' debe ser un email válido."), 400
    if not isinstance(text, str) or not text.strip():
        return jsonify(error="El campo 'text' es obligatorio."), 400

    try:
        creds = authenticate_gmail()
        service = build('gmail', 'v1', credentials=creds)
        message = create_message_html(
            sender=SENDER_EMAIL,
            to=recipient.strip(),
            subject=DEFAULT_SUBJECT,
            html_content=text,
        )
        sent_message = send_message(service, 'me', message)
    except Exception as error:
        app.logger.exception("No se pudo enviar el correo")
        return jsonify(error="No se pudo enviar el correo.", detail=str(error)), 500

    return jsonify(
        message="Correo enviado correctamente.",
        id=sent_message['id'],
    ), 200

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
