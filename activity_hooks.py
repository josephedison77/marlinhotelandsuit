from sqlalchemy import event
from flask import has_request_context
from flask_login import current_user
from datetime import datetime

def log_crud_event(mapper, connection, target, action):
    from models import ActivityLog, db  # Avoid circular import
    user_id = None
    username = "System"
    if has_request_context() and hasattr(current_user, "id"):
        try:
            user_id = current_user.id
            username = current_user.username
        except Exception:
            pass
    log = ActivityLog(
        title=f"{target.__class__.__name__} {action.capitalize()}",
        description=f"{action.capitalize()} on {target.__class__.__name__} (ID: {getattr(target, 'id', 'N/A')}) by {username}",
        initiator_id=user_id,
        timestamp=datetime.utcnow()
    )
    db.session.add(log)
    db.session.commit()

def after_insert(mapper, connection, target):
    log_crud_event(mapper, connection, target, "created")

def after_update(mapper, connection, target):
    log_crud_event(mapper, connection, target, "updated")

def after_delete(mapper, connection, target):
    log_crud_event(mapper, connection, target, "deleted")

# Attach to models you want to track
from models import Room, MaintenanceRequest, Booking, Staff, CleaningLog

for model in [Room, MaintenanceRequest, Booking, Staff, CleaningLog]:
    event.listen(model, 'after_insert', after_insert)
    event.listen(model, 'after_update', after_update)
    event.listen(model, 'after_delete', after_delete)