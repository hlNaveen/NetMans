import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

sender_email = 'netmansautomail@gmail.com'
password = 'hogmjgkmqodaozlp'

def send_email(sender, subject, body):
    global sender_email
    global password

    receiver_email = sender
    
    message = MIMEMultipart()
    message['From'] = sender_email
    message['To'] = receiver_email
    message['Subject'] = subject

    body = body
    message.attach(MIMEText(body, 'plain'))

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(sender_email, password)

    text = message.as_string()

    try:
        server.sendmail(sender_email, receiver_email, text)
        print("Email Sent Successfully !")
    except:
        return False

    server.quit()

    return True