# utils.py
from flask_mail import Message
from flask import current_app
from flask_mail import Mail, Message

mail = Mail()

def send_email(to_email, subject, body):
    try:
        msg = Message(
            subject=subject,
            recipients=[to_email],
            body=body,
            sender=current_app.config['MAIL_DEFAULT_SENDER']
        )
        mail.send(msg)
        current_app.logger.info(f"Email sent to {to_email}")
    except Exception as e:
        current_app.logger.error(f"Error sending email: {str(e)}")