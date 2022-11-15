#Python Built-in Library
from smtplib import SMTP_SSL as SMTP


# from email.mime.multipart import MIMEMultipart
# from email.mime.text import MIMEText
# from email.utils import formatdate
#External Python Mods

class Mail:

    def send_email(to: str, subject: str, body: str):
        if not DEBUG:
            # Update config doc
            # noinspection PyShadowingNames
            config_doc = db["config"].find_one()

            msg = MIMEMultipart()  #??
            # Build the MIME email
            msg = MIMEText(body, "plain")
            msg["Subject"] = subject
            msg["To"] = to
            msg["From"] = config_doc["email"]["address"]
            msg["reply-to"] = 'noReply@airgapped.io'
            msg["Date"] = formatdate(localtime=True)

            # Connect and send the email
            server = SMTP(config_doc["email"]["server"])
            server.login(config_doc["email"]["address"], config_doc["email"]["password"])
            server.sendmail(config_doc["email"]["address"], [to], msg.as_string())
            server.quit()
        else:
            print(f"Debug mode set, would send email to {to} subject {subject}")
