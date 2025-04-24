from utils.utils import Notification

def print_notifications(response: Notification) -> None:
    """Handles the notifications received from the server."""
    if response.notifications is not None:
        if len(response.notifications) == 0:
            print("No new notifications.")
        else:
            print(f"You have {len(response.notifications)} new notifications.")
            for notification in response.notifications:
                print(f"- {notification['content']} (Received at: {notification['timestamp']})")
    else:
        print("Failed to receive notifications.")
