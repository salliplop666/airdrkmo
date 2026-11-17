import smtplib
from email.message import EmailMessage

from app.core.config import settings


def send_smtp(to: str, subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = settings.smtp_from, to, subject
    msg.set_content(body)
    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as s:
        if settings.smtp_starttls:
            s.starttls()
        if settings.smtp_user and settings.smtp_password:
            s.login(settings.smtp_user, settings.smtp_password.get_secret_value())
        s.send_message(msg)
