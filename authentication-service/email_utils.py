import os
import smtplib
from email.mime.text import MIMEText

def send_otp_email(to_email: str, otp: str) -> None:
    """
    SMTP sender. Railway Variables (REQUIRED):
    SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_FROM
    """

    # Fail-fast: mag-eerror agad kung wala sa env
    host = os.environ["SMTP_HOST"]
    port = int(os.environ["SMTP_PORT"])
    user = os.environ["SMTP_USER"]
    password = os.environ["SMTP_PASSWORD"]
    from_email = os.environ["SMTP_FROM"]

    subject = "Your Password Reset OTP"
    body = (
        f"Your OTP code is: {otp}\n\n"
        "This code expires in 10 minutes.\n"
        "If you did not request this, you can ignore this email."
    )

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = from_email
    msg["To"] = to_email

    with smtplib.SMTP(host, port) as server:
        server.starttls()
        server.login(user, password)
        server.sendmail(from_email, [to_email], msg.as_string())
