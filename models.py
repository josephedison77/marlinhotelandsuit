from datetime import datetime, timezone, UTC
from flask_login import UserMixin
from sqlalchemy import and_
from flask import url_for
from datetime import datetime, timedelta
# Add this at the end of models.py
from sqlalchemy import event
from flask import has_request_context
from flask_login import current_user

import secrets
# Add this import instead:
from extensions import db

# Association table for many-to-many relationship between Users and Roles
user_roles = db.Table('user_roles',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True)
)

class Automation(db.Model):
    __tablename__ = 'automation'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    trigger_type = db.Column(db.String(50), nullable=False)
    action_type = db.Column(db.String(50), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    trigger_config = db.Column(db.JSON, default={})
    action_config = db.Column(db.JSON, default={})
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<Automation {self.name}>'

class AdminRegistrationToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(128), unique=True)
    generated_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True)
    description = db.Column(db.String(200))

    def __repr__(self):
        return f'<Role {self.name}>'

class APIKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.String(64), unique=True, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    is_revoked = db.Column(db.Boolean, default=False)
    revoked_at = db.Column(db.DateTime)

    def is_valid(self):
        return not self.is_revoked and datetime.utcnow() < self.expires_at

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(64), nullable=False, unique=True)
    last_name = db.Column(db.String(64), nullable=False, unique=True)
    phone_number = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(256), nullable=False)
    last_login = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    otp = db.Column(db.String(6), nullable=True)
    otp_expiry = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    email_verified = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(20), default='pending')
    approved_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    is_main_admin = db.Column(db.Boolean, default=False)
    approved_by_user = db.relationship(
        'User', 
        remote_side=[id],
        foreign_keys=[approved_by],
        uselist=False
    )
    # Relationships
    roles = db.relationship('Role', secondary=user_roles, backref=db.backref('users', lazy='dynamic'))
    notifications = db.relationship('Notification', back_populates='user', lazy='dynamic')
    bookings = db.relationship('Booking', backref='user', lazy=True)
    reports = db.relationship('Report', backref='user', lazy='dynamic')
    feedbacks = db.relationship('Feedback', backref='user', lazy=True)
    
     # ADD THIS PROPERTY
    @property
    def unread_notifications(self):
        """Return count of unread notifications for this user"""
        if hasattr(self, '_unread_notifications'):
            return self._unread_notifications
            
        # Count unread notifications
        count = Notification.query.filter_by(
            user_id=self.id,
            is_read=False
        ).count()
        
        # Cache the result to avoid repeated queries
        self._unread_notifications = count
        return count
    reported_issues = db.relationship(
        'MaintenanceRequest',
        back_populates='reported_by',
        overlaps="reporter,reported_issues",
        foreign_keys='MaintenanceRequest.reported_by_id'
    )

   
    def has_role(self, role_name):
        return any(role.name == role_name for role in self.roles)

    def __repr__(self):
        return f'<User {self.username}>'
    
    def unread_notifications(self):
        return Notification.query.filter_by(
            user_id=self.id,
            is_read=False
        ).count()
    


class GalleryImage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)



class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Numeric(10, 2), nullable=False)
    capacity = db.Column(db.Integer, nullable=False)
    size = db.Column(db.Integer, nullable=False)
    is_active = db.Column(db.Boolean, default=True)  # Add this line
    room_type = db.Column(db.String(50), nullable=False)  # e.g., 'single', 'double', 'suite'
    floor = db.Column(db.String(50), nullable=False)  # e.g., '1st', '2nd', '3rd'
    bedsize = db.Column(db.Integer, nullable=False)
    amenities = db.Column(db.JSON, nullable=False)
    cleaning_status = db.Column(db.String(20), default='clean')  # clean, dirty, assigned, in_pr
    status = db.Column(db.Enum(
        'available', 
        'reserved',  # New status for pending payments
        'booked', 
        'occupied', 
        'maintenance', 
        name='room_status'), 
        default='available'
    )
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    last_cleaned = db.Column(db.DateTime)
    last_occupied = db.Column(db.Date)  # Date of last checkout
    # Relationships
    images = db.relationship('RoomImage', backref='room', lazy=True)
    bookings = db.relationship('Booking', backref='room', lazy=True)
    
    maintenance_requests = db.relationship('MaintenanceRequest', backref='room', lazy=True)

    def __repr__(self):
        return f'<Room {self.name}>'





class Expense(db.Model):
    __tablename__ = 'expense'
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False)
    amount = db.Column(db.Numeric(10, 2), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    vendor = db.Column(db.String(100))
    payment_method = db.Column(db.String(50))
    recorded_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    document_path = db.Column(db.String(255))  # For storing receipts/invoices

    # Relationships
    recorder = db.relationship('User', backref='expenses')


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    __tablename__ = 'notification'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', back_populates='notifications')
    title = db.Column(db.String(100))
    message = db.Column(db.Text)
    category = db.Column(db.String(50))
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)
    action_url = db.Column(db.String(255))

    def __repr__(self):
        return f'<Notification {self.title}>'
    
    @property
    def timestamp(self):
        """Alias for created_at to match template expectations"""
        return self.created_at

    @classmethod
    def send_admin_approval_notification(cls, new_admin):
        """Notify existing admins about new admin registration"""
        admin_role = Role.query.filter_by(name='admin').first()
        if admin_role:
            admins = admin_role.users.filter_by(status='approved').all()
            for admin in admins:
                notification = Notification(
                    user_id=admin.id,
                    title="New Admin Approval Request",
                    message=f"New admin registration requires approval: {new_admin.email}",
                    category="admin"
                )
                db.session.add(notification)
            db.session.commit()

    @classmethod
    def send_order_notification(cls, order):
        """Notify staff about new orders"""
        staff_role = Role.query.filter_by(name='staff').first()
        if staff_role:
            for staff in staff_role.users:
                notification = Notification(
                    user_id=staff.id,
                    title="New Order Received",
                    message=f"Table {order.table_number} - Order #{order.id}",
                    category="order",
                    action_url=url_for('order_details', order_id=order.id)
                )
                db.session.add(notification)
            db.session.commit()

    @classmethod
    def send_shift_notification(cls, user_id, message):
        """Create shift notification without email sending"""
        notification = Notification(
            user_id=user_id,
            title="Shift Reminder",
            message=message,
            category="shift"
        )
        db.session.add(notification)
        db.session.commit()

    def unread_notifications(self):
        return Notification.query.filter_by(user_id=self.id, is_read=False).count()
    
    
    @classmethod
    def send_to_user(cls, user_id, title, message, category="general"):
        notification = cls(
            user_id=user_id,
            title=title,
            message=message,
            category=category
        )
        db.session.add(notification)
        db.session.commit()


class Report(db.Model):
    __tablename__ = 'report'
    id = db.Column(db.Integer, primary_key=True)
    report_type = db.Column(db.String(50))
    parameters = db.Column(db.JSON)
    generated_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    status = db.Column(db.String(20), default='pending')
    file_path = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)

class RoomImage(db.Model):
    __tablename__ = 'room_image'
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    is_primary = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Booking(db.Model):
    __tablename__ = 'booking'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id', ondelete='CASCADE'), nullable=False)
    check_in_date = db.Column(db.DateTime, nullable=False)
    check_out_date = db.Column(db.DateTime, nullable=False)
    booking_date = db.Column(db.DateTime, default=datetime.utcnow)
    is_rated = db.Column(db.Boolean, default=False) 
    # Add to Booking model
    reminder_sent = db.Column(db.Boolean, default=False)
    checked_out = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(20), default='Reserved')
    total_amount = db.Column(db.Numeric(10, 2), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    payment_status = db.Column(db.String(20), default='Pending')
    otp = db.Column(db.String(6))
    otp_expiry = db.Column(db.DateTime)
    check_in_status = db.Column(db.String(20), default='Pending')
    check_out_status = db.Column(db.String(20), default='Pending')
    checkout_otp = db.Column(db.String(6))
    checkout_otp_expiry = db.Column(db.DateTime)
    auto_checked_out = db.Column(db.Boolean, default=False)
    checked_out_at = db.Column(db.DateTime)
    check_in_otp = db.Column(db.String(6))
    payment_date = db.Column(db.DateTime)
    payment_reference = db.Column(db.String(100))
    cancellation_requested = db.Column(db.Boolean, default=False)
    cancellation_reason = db.Column(db.Text)
    cancellation_status = db.Column(db.String(20), default='none')
    cancellation_requested_at = db.Column(db.DateTime)
    original_check_in = db.Column(db.Date)
    original_check_out = db.Column(db.Date)
    cancellation_approved_at = db.Column(db.DateTime)
    cancellation_denied_at = db.Column(db.DateTime)
    cancellation_otp = db.Column(db.String(6))
    cancellation_otp_expiry = db.Column(db.DateTime)
    booking_source = db.Column(db.String(50), default='direct')  # Add this line
    late_checkout = db.Column(db.Boolean, default=False)
    late_checkout_fee = db.Column(db.Float, default=0.0)
    
    def __repr__(self):
        return f'<Booking {self.id}>'
    
    def generate_checkout_otp(self):
        # Generate 6-digit OTP valid for 30 minutes
        self.checkout_otp = secrets.randbelow(1000000)  # 0-999999
        self.checkout_otp = str(self.checkout_otp).zfill(6)  # Pad to 6 digits
        self.checkout_otp_expiry = datetime.utcnow() + timedelta(minutes=30)
        return self.checkout_otp
    
    def is_otp_valid(self):
        if not self.checkout_otp or not self.checkout_otp_expiry:
            return False
        return datetime.utcnow() < self.checkout_otp_expiry
    
    def generate_rating_url(self):
        return url_for('rate_booking', booking_id=self.id, _external=True)

class Staff(db.Model):
    __tablename__ = 'staff'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    role = db.Column(db.String(50), nullable=False)
    position = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    phone_number = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    profile_image = db.Column(db.String(255))
    shifts = db.relationship('Shift', backref='staff', lazy=True)
    user = db.relationship(
        'User', 
        backref=db.backref('staff_profile', uselist=False),
        foreign_keys=[user_id]
    )
    maintenance_tasks = db.relationship('MaintenanceRequest', backref='staff', lazy=True)
    staff_id = db.Column(db.String(20), unique=True, index=True)  # Removed default

    __table_args__ = (
        db.UniqueConstraint('user_id', name='uq_staff_user_id'),
    )
    
    def __repr__(self):
        return f'<Staff {self.first_name} {self.last_name}>'
    
        # In Staff model
    def get_staff_on_duty(shift_type=None):
        now = datetime.now(timezone.utc)
        query = Staff.query.filter(
            Staff.position == 'Housekeeper',
            Staff.is_active == True,
            Staff.shifts.any(
                and_(
                    Shift.start_time <= now,
                    Shift.end_time >= now
                )
            )
        )
        
        if shift_type:
            query = query.filter(
                Staff.shifts.any(Shift.shift_type == shift_type)
            )
            
        return query.all()

# Generate staff ID function
def generate_staff_id():
    year = datetime.now().year
    last_staff = Staff.query.order_by(Staff.id.desc()).first()
    sequence = last_staff.id + 1 if last_staff else 1
    return f"HM-{year}-{str(sequence).zfill(4)}"

# Event listener to assign staff_id before insert
@event.listens_for(Staff, 'before_insert')
def assign_staff_id(mapper, connection, target):
    target.staff_id = generate_staff_id()

class ActivityLog(db.Model):
    __tablename__ = 'activity_log'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255))
    description = db.Column(db.Text)
    initiator_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # <-- THIS LINE
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    initiator = db.relationship('User', backref='activity_logs')



class Shift(db.Model):
    __tablename__ = 'shift'
    id = db.Column(db.Integer, primary_key=True)
    staff_id = db.Column(db.Integer, db.ForeignKey('staff.id'), nullable=False)
    shift_type = db.Column(db.String(20))
    shift_date = db.Column(db.Date, nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    notified = db.Column(db.Boolean, default=False)
    reminder_sent = db.Column(db.Boolean, default=False)
    position = db.Column(db.String(50))
    attendance_otp = db.Column(db.String(6), nullable=True)
    otp_generated_at = db.Column(db.DateTime, nullable=True)
    otp_expiry = db.Column(db.DateTime, nullable=True)
    attendance_status = db.Column(db.String(20), default='pending')
    otp_sent_at = db.Column(db.DateTime)
    otp_attempts = db.Column(db.Integer, default=0)
    checkin_otp = db.Column(db.String(6))
    checkin_otp_expiry = db.Column(db.DateTime)
    checkout_otp = db.Column(db.String(6), nullable=True)
    checkout_otp_expiry = db.Column(db.DateTime, nullable=True)
    
    # Fixed relationship
    attendance_records = db.relationship(
        'Attendance', 
        backref='shift_record',
        foreign_keys='Attendance.shift_id',
        lazy=True
    )

# In models.py - update Attendance model
class Attendance(db.Model):
    __tablename__ = 'attendance'
    id = db.Column(db.Integer, primary_key=True)
    staff_id = db.Column(db.Integer, db.ForeignKey('staff.id', ondelete='CASCADE'), nullable=False)
    shift_id = db.Column(db.Integer, db.ForeignKey('shift.id'), nullable=True)
    clock_in_time = db.Column(db.DateTime, nullable=True)  # Changed to nullable
    clock_out_time = db.Column(db.DateTime, nullable=True)
    date = db.Column(db.Date, default=lambda: datetime.now(UTC).date())
    status = db.Column(db.String(20), default='pending')  # Add status field
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    staff = db.relationship('Staff', backref='attendance_records', foreign_keys=[staff_id])


class BarItem(db.Model):
    __tablename__ = 'bar_item'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, index=True)
    description = db.Column(db.Text)
    price = db.Column(db.Numeric(10, 2), nullable=False)
    quantity = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    image = db.Column(db.String(255), nullable=True)  # Add this field

    def __repr__(self):
        return f'<BarItem {self.name}>'

class BarSale(db.Model):
    __tablename__ = 'bar_sale'
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey('bar_item.id', ondelete='CASCADE'), nullable=False)
    quantity_sold = db.Column(db.Integer, nullable=False)
    sale_time = db.Column(db.DateTime, default=datetime.utcnow)
    total_amount = db.Column(db.Numeric(10, 2), nullable=False)

    
    staff_id = db.Column(db.Integer, db.ForeignKey('staff.id'))
    staff = db.relationship('Staff', backref='sales')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    item = db.relationship('BarItem', backref='sales')


class BarOrder(db.Model):
    __tablename__ = 'bar_order'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='bar_orders')  # <-- Add this line
    table_number = db.Column(db.String(50), nullable=False)
    total_amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='pending')
    payment_status = db.Column(db.String(20), default='pending')
    payment_reference = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_printed = db.Column(db.Boolean, default=False)
    order_items = db.relationship('OrderItem', backref='order', lazy=True)

class OrderItem(db.Model):
    __tablename__ = 'order_item'
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('bar_order.id'))
    item_id = db.Column(db.Integer, db.ForeignKey('bar_item.id'))
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Numeric(10, 2), nullable=False)
    item = db.relationship('BarItem')


class Payment(db.Model):
    __tablename__ = 'payment'
    id = db.Column(db.Integer, primary_key=True)
    booking_id = db.Column(db.Integer, db.ForeignKey('booking.id'))
    amount = db.Column(db.Numeric(10, 2), nullable=False)
    reference = db.Column(db.String(100), unique=True)
    status = db.Column(db.String(20), default='pending')
    payment_method = db.Column(db.String(50))
    payment_date = db.Column(db.DateTime)
    paystack_response = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (
        db.Index('idx_payment_created_at', 'created_at'),
        db.Index('idx_payment_booking', 'booking_id'),
    )
# models.py - Updated Cleaning Models
class CleaningAssignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=False)
    staff_id = db.Column(db.Integer, db.ForeignKey('staff.id'), nullable=False)
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow)
    due_by = db.Column(db.DateTime)
    status = db.Column(db.String(20), default='pending')  # pending, in_progress, completed
    priority = db.Column(db.Integer, default=2)  # 1=high, 2=medium, 3=low
    estimated_duration = db.Column(db.Integer)  # minutes
    cleaning_log = db.relationship(
    'CleaningLog', 
    backref=db.backref('cleaning_assignment', uselist=False),  # Changed backref name
    uselist=False, 
    lazy=True)
    room = db.relationship('Room', backref='assignments')
    staff = db.relationship('Staff', backref='assignments')
    completed_at = db.Column(db.DateTime)  # Add this line
    
    def to_dict(self):
        return {
            'id': self.id,
            'room': self.room.name,
            'staff': f"{self.staff.first_name} {self.staff.last_name}",
            'status': self.status,
            'priority': self.priority,
            'due_by': self.due_by.isoformat() if self.due_by else None,
            'duration': self.estimated_duration
        }

class CleaningLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    assignment_id = db.Column(db.Integer, db.ForeignKey('cleaning_assignment.id'), nullable=False)
    start_time = db.Column(db.DateTime)
    end_time = db.Column(db.DateTime)
    notes = db.Column(db.Text)
    status = db.Column(db.String(20))  # completed, skipped, needs_attention
    quality_check = db.Column(db.Boolean, default=False)
    staff_id = db.Column(db.Integer, db.ForeignKey('staff.id')) 
    staff = db.Column(db.Integer, db.ForeignKey('staff.id')) 
    
    
    @property
    def duration(self):
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds() / 60
        return None

    # Add this property to access room via cleaning assignment
    @property
    def room(self):
        if self.cleaning_assignment:
            return self.cleaning_assignment.room
        return None

class MaintenanceRequest(db.Model):
    __tablename__ = 'maintenance_request'
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'))
    staff_id = db.Column(db.Integer, db.ForeignKey('staff.id'))
    request_time = db.Column(db.DateTime, default=datetime.utcnow)
    issue_type = db.Column(db.String(50))
    description = db.Column(db.Text)
    status = db.Column(db.String(20), default='Open')
    priority = db.Column(db.String(20), default='Medium')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime)
    notes = db.Column(db.Text)
    reported_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    reported_by = db.relationship(
        'User',
        back_populates='reported_issues',
        overlaps="reporter,reported_issues"
    )

class Feedback(db.Model):
    __tablename__ = 'feedback'
    id = db.Column(db.Integer, primary_key=True)
    booking_id = db.Column(db.Integer, db.ForeignKey('booking.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    rating = db.Column(db.Integer)
    comments = db.Column(db.Text)
    response = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Rating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    booking_id = db.Column(db.Integer, db.ForeignKey('booking.id'))
    rating = db.Column(db.Integer, nullable=False)
    comments = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_rated = db.Column(db.Boolean, default=False)  # Add this field
    booking = db.relationship('Booking', backref=db.backref('rating', uselist=False))



def log_crud_event(target, action):
    user_id = None
    username = "System"
    
    if has_request_context() and hasattr(current_user, "id"):
        try:
            user_id = current_user.id
            username = current_user.username
        except Exception:
            pass
    
    from sqlalchemy import event

    # Example event listener for a specific model (replace 'Room' with your model if needed)
    # @event.listens_for(Room, 'after_insert')
    # def log_insert(mapper, connection, target):
    #     connection.execute(
    #         Log.__table__.insert(),
    #         {"message": "Something happened"}
    #     )

def after_insert(mapper, connection, target):
    log_crud_event(target, "created")

def after_update(mapper, connection, target):
    log_crud_event(target, "updated")

def after_delete(mapper, connection, target):
    log_crud_event(target, "deleted")

# Attach hooks to all relevant models
models_to_track = [
    Room, MaintenanceRequest, Booking, Staff, CleaningLog,
    User, Role, BarItem, BarSale, BarOrder, Payment,
    Feedback, Notification, Report, Shift, Attendance,
    CleaningAssignment, APIKey, AdminRegistrationToken
]

for model in models_to_track:
    event.listen(model, 'after_insert', after_insert)
    event.listen(model, 'after_update', after_update)
    event.listen(model, 'after_delete', after_delete)

# Add to models.py
class InventoryUsage(db.Model):
    __tablename__ = 'inventory_usage'
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey('store_inventory.id'), nullable=False)
    quantity_used = db.Column(db.Integer, nullable=False)
    used_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    used_at = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.Column(db.Text)
    
    item = db.relationship('StoreInventory', backref='usage_records')
    used_by = db.relationship('User', foreign_keys=[used_by_id])

class InventoryRequest(db.Model):
    __tablename__ = 'inventory_request'
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey('store_inventory.id'), nullable=False)
    quantity_requested = db.Column(db.Integer, nullable=False)
    requested_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    requested_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    approved_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    approved_at = db.Column(db.DateTime, nullable=True)
    notes = db.Column(db.Text)
    
    item = db.relationship('StoreInventory', backref='requests')
    requested_by = db.relationship('User', foreign_keys=[requested_by_id])
    approved_by = db.relationship('User', foreign_keys=[approved_by_id])

class StoreInventory(db.Model):
    __tablename__ = 'store_inventory'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    category = db.Column(db.String(50))  # e.g., 'linen', 'toiletries', 'cleaning supplies'
    unit = db.Column(db.String(20))  # e.g., 'pieces', 'liters', 'kg'
    quantity = db.Column(db.Integer, default=0)
    reorder_level = db.Column(db.Integer, default=10)
    unit_cost = db.Column(db.Numeric(10, 2), nullable=False)
    supplier = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    updated_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    created_by = db.relationship('User', foreign_keys=[created_by_id])
    updated_by = db.relationship('User', foreign_keys=[updated_by_id])
    
    def __repr__(self):
        return f'<StoreInventory {self.name}>'