from datetime import datetime
from utils.utils import Notification

def print_notifications(response: Notification) -> None:
    """Handles the notifications received from the server."""
    if response.notifications is not None:
        if len(response.notifications) == 0:
            print("No new notifications.")
        else:
            print(f"You have {len(response.notifications)} new notifications.")
            for notification in response.notifications:
                created_at = datetime.strptime(notification['timestamp'], "%Y-%m-%dT%H:%M:%S.%fZ")
                readable_date = created_at.strftime("%d-%m-%Y %H:%M:%S")
                print(f"- {notification['content']} (Received at: {readable_date})")
    else:
        print("Failed to receive notifications.")
