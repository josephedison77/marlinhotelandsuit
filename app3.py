from datetime import datetime, timedelta
from app import db
from models import Booking, Room

now = datetime.utcnow()
expired_bookings = Booking.query.filter(
    Booking.otp_expiry < now,
    Booking.check_in_status == 'Pending'
).all()

for booking in expired_bookings:
    booking.check_in_status = 'Expired'
    room = Room.query.get(booking.room_id)
    if room:
        room.status = 'available'

db.session.commit()