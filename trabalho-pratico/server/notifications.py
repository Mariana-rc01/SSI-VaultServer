from datetime import datetime
from server.utils_db import load_notifications, save_notifications

def add_notification(userid: str, message: str) -> None:
    """Adds a notification to the user's notifications list."""
    notifications = load_notifications()

    user_notifications = next((n for n in notifications if n["userId"] == userid), None)
    if user_notifications is None:
        # If the user does not exist, create a new entry
        user_notifications = {
            "userId": userid,
            "notifications": []
        }
        notifications.append(user_notifications)

    user_notifications["notifications"].append({
        "content": message,
        "timestamp": datetime.now().isoformat() + "Z",
        "read": False
    })

    save_notifications(notifications)

def get_notifications(userid: str) -> list:
    """Returns the notifications for the user with the property "read" as false and set it to true."""
    notifications = load_notifications()

    user_notifications = next((n for n in notifications if n["userId"] == userid), None)
    if user_notifications is None:
        return []

    unread_notifications = [n for n in user_notifications["notifications"] if not n["read"]]
    for n in unread_notifications:
        n["read"] = True

    save_notifications(notifications)
    return unread_notifications