import socket
import boto3
from IPLogger import logger

###############################################################################################################

def alert_owner():
    hostname, ip_address = machine_info()
    
    message = f"""
    [SECURITY ALERT] Suspicious Activity Detected On:
    Machine Name: {hostname}
    IP Address: {ip_address}
    """
    
    region = 'eu-north-1'
    sns_arn = "arn:aws:sns:eu-north-1:061039782188:Security_Alert"

    sns_client = boto3.client('sns', region_name=region)
    
    try:
        response = sns_client.publish(
            TopicArn=sns_arn,
            Message=message
        )
        print(f"[!] Message sent. Message ID: {response['MessageId']}")
        message = f"[!] Message sent Message ID: {response['MessageId']}"
        logger(message)
    except Exception as e:
        print(f"[!] Error sending message: {e}")
        message = f"[!] Error sending message: {e}"
        logger(message)

def machine_info():
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        return hostname, ip_address
    except Exception as e:
        print(f"[!] WARNING Failed getting machine info: {e}")
        return "Unknown", "Unknown"

###############################################################################################################