from flask import Flask, jsonify, request, make_response, render_template, redirect, url_for, session, flash, abort,send_from_directory
from flask_migrate import Migrate
from functools import wraps
import jwt
from sqlalchemy.exc import IntegrityError
from datetime import datetime, timedelta, timezone, time
from werkzeug.security import generate_password_hash, check_password_hash
import random
import traceback
from dateutil.relativedelta import relativedelta
import pytz
from sqlalchemy import select
from sqlalchemy.orm import joinedload
# import automation_engine
from datetime import time as time_object
import humanize
from datetime import datetime, timedelta, timezone, time as dt_time 
import string
from sqlalchemy import case, extract
from datetime import date
from flask import jsonify
import json
from flask import current_app 
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from flask import make_response
import csv
from utils import send_email
from flask import make_response 
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from io import BytesIO
from io import StringIO
from flask_migrate import Migrate
from threading import Thread
import logging
from collections import defaultdict
from sqlalchemy import extract, func
from logging.handlers import RotatingFileHandler
 # Add this import
from flask_login import  LoginManager,login_user, logout_user, current_user,login_required
import os
from flask_wtf.csrf import CSRFProtect
from werkzeug.exceptions import HTTPException, InternalServerError, NotFound, Unauthorized, BadRequest
from extensions import db, mail

from werkzeug.utils import secure_filename
import filetype
from sqlalchemy import func, and_
from io import BytesIO
import base64
from apscheduler.schedulers.background import BackgroundScheduler
from PIL import Image
from sqlalchemy import or_
import time
import secrets
from flask import render_template_string

import uuid
from dotenv import load_dotenv
load_dotenv() 

import uuid
        
app = Flask(__name__)
# Configuration - Security First Approach

# 1. Application Security - ADDED FALLBACK DEFAULTS
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'fallback-secret-key-for-development')
app.config['ADMIN_REG_TOKEN'] = os.environ.get('ADMIN_REG_TOKEN', 'default-admin-token')

# 2. Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///hotel.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 3. JWT Configuration
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=30)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=7)

# 4. File Uploads
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static/uploads')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# 5. Email Configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')

# 6. Payment Gateway (Paystack)
app.config['PAYSTACK_SECRET_KEY'] = os.environ.get('PAYSTACK_SECRET_KEY', '')
app.config['PAYSTACK_PUBLIC_KEY'] = os.environ.get('PAYSTACK_PUBLIC_KEY', '')
app.config['PAYSTACK_BASE_URL'] = 'https://api.paystack.co'

# 7. Google Services
app.config['GOOGLE_MAPS_API_KEY'] = os.environ.get('GOOGLE_MAPS_API_KEY', '')

# Security Salt - ADDED FALLBACK
app.config['SECURITY_PASSWORD_SALT'] = os.environ.get('SECURITY_PASSWORD_SALT', 'another-secret-salt')
app.config['SECURITY_REGISTERABLE'] = True
app.config['SECURITY_SEND_REGISTER_EMAIL'] = False

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['BAR_ITEM_UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static/bar_items')
os.makedirs(app.config['BAR_ITEM_UPLOAD_FOLDER'], exist_ok=True)

from forms import LoginForm, BookingForm, InventoryForm,RegistrationForm, ExpenseForm,RoomForm,RatingForm, EditProfileForm, PostForm, AdminLoginForm,AdminRegistrationForm, StaffRegistrationForm, AutomationForm, ReportForm, NotificationForm,ContactForm, ResetPasswordForm, ResetPasswordRequestForm, StaffEditForm, BarItemForm,UserSettingsForm, InventoryUsageForm, InventoryRequestForm
import requests

# Initialize serializer - FIXED WITH DEFAULT SECRET
ts = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Import models AFTER initializing db
from models import (
    User, Room, APIKey, Role, Booking, ActivityLog, Staff, Attendance,
    BarItem, Feedback, Shift, BarSale, CleaningLog, Payment,
    MaintenanceRequest, RoomImage, Notification, Automation, Report,
    BarOrder, OrderItem, AdminRegistrationToken, CleaningAssignment, Rating, GalleryImage, Expense, StoreInventory, InventoryRequest, InventoryUsage
)

# Initialize extensions
csrf = CSRFProtect(app)
db.init_app(app)
migrate = Migrate(app, db)
mail = Mail(app)
mail.init_app(app)

s = URLSafeTimedSerializer(app.config['SECRET_KEY'])  # Secondary serializer

# Logging Configuration
log_handler = RotatingFileHandler(
    filename='hotel.log',
    maxBytes=1024 * 1024 * 5,
    backupCount=5,
    encoding='utf-8'
)
log_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
log_handler.setFormatter(formatter)
app.logger.addHandler(log_handler)
app.logger.setLevel(logging.INFO)


NIGERIA_TZ = pytz.timezone('Africa/Lagos')
CHECKOUT_TIME = dt_time(12, 0)  # 12:00 PM Nigeria time
# Utility Functions
def generate_otp(length=6):
    return ''.join(random.choice(string.digits) for _ in range(length))


def send_email(to_email, subject, body):
    try:
        msg = Message(
            subject=subject,
            recipients=[to_email],
            body=body,
            sender=app.config['MAIL_DEFAULT_SENDER']
        )
        mail.send(msg)
        app.logger.info(f"Email sent to {to_email}")
    except Exception as e:
        app.logger.error(f"Error sending email: {str(e)}")


def create_jwt_token(user_id, role, token_type):
    expires_delta = app.config['JWT_ACCESS_TOKEN_EXPIRES'] if token_type == 'access' else app.config['JWT_REFRESH_TOKEN_EXPIRES']
    payload = {
        'exp': datetime.now(NIGERIA_TZ) + expires_delta,
        'iat': datetime.now(NIGERIA_TZ),
        'sub': user_id,
        'role': role,
        'type': token_type
    }
    try:
        return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    except Exception as e:
        app.logger.error(f"Error creating JWT token: {e}")
        raise InternalServerError("Failed to create token")

# Initial roles setup
initial_roles = [
    'super_admin', 
    'admin', 
    'staff', 
    'user', 
    'api_manager',
    'hr',
    'bar_manager',
    'finance_admin',
    'receptionist',
    'api_management',
    'housekeeping_supervisor'
    'store_keeper'
]

def verify_jwt_token(token):
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return 'Token expired'
    except jwt.InvalidTokenError:
        return 'Invalid token'
    except Exception as e:
        app.logger.error(f"Error verifying JWT token: {e}")
        return 'Invalid token'

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def verify_payment(reference):
    url = f"{current_app.config['PAYSTACK_BASE_URL']}/transaction/verify/{reference}"
    headers = {
        "Authorization": f"Bearer {current_app.config['PAYSTACK_SECRET_KEY']}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Paystack verification error: {e}")
        return None


def get_active_housekeepers():
    now = datetime.now(NIGERIA_TZ)
    return Staff.query.filter(
        Staff.position == 'Housekeeper',
        Staff.is_active == True,
        Staff.shifts.any(and_(
            Shift.start_time <= now,
            Shift.end_time >= now
        ))
    ).all()

def process_refund(booking, percent=1.0):
    if hasattr(booking, 'payment_method') and booking.payment_method == 'Paystack':
        url = f"{app.config['PAYSTACK_BASE_URL']}/refund"
        headers = {
            "Authorization": f"Bearer {app.config['PAYSTACK_SECRET_KEY']}",
            "Content-Type": "application/json"
        }
        refund_amount = int(booking.total_amount * percent * 100)
        payload = {
            "transaction": booking.payment_reference,
            "amount": refund_amount
        }
        try:
            response = requests.post(url, headers=headers, json=payload)
            if response.json().get('status'):
                return True
        except Exception as e:
            app.logger.error(f"Refund failed: {e}")
    return False

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

login_manager = LoginManager(app)
login_manager.login_view = 'login'  # This sets the default login route

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def room_management_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        if not any(role.name in ['super_admin', 'admin', 'housekeeping_supervisor'] for role in current_user.roles):
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def housekeeping_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        if not any(role.name in ['super_admin', 'housekeeping_supervisor'] for role in current_user.roles):
            abort(403)
        return f(*args, **kwargs)
    return decorated_function



# Custom filter for datetime formatting
@app.template_filter('datetimeformat')
def datetimeformat(value, format='%Y-%m-%d %H:%M'):
    if value is None:
        return ""
    # Convert UTC to Nigeria time
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(NIGERIA_TZ).strftime(format)

# Custom filter for currency formatting
@app.template_filter('format_currency')
def format_currency(value):
    try:
        return "₦{:,.2f}".format(float(value))
    except (ValueError, TypeError):
        return "₦0.00"

def role_required(role_name):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.has_role(role_name):
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('admin_login'))
        if not any(role.name in ['super_admin', 'admin'] for role in current_user.roles):
            abort(403)
        if current_user.status != 'approved':
            flash('Your account is pending approval', 'warning')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

@app.template_filter('number_format')
def number_format(value):
    return "{:,.2f}".format(value)

# Add this to your main app file
@app.template_filter('datetimeformat')
def datetimeformat(value, format='%Y-%m-%d %H:%M'):
    if value is None:
        return "Now"
    return value.strftime(format)

def role_required(allowed_roles):
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            if not any(current_user.has_role(role) for role in allowed_roles):
                if current_user.has_role('admin'):
                    return redirect(url_for('admin_dashboard'))
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def initialize_paystack_payment(email, amount, reference, metadata=None, callback_type='booking'):
    url = f"{current_app.config['PAYSTACK_BASE_URL']}/transaction/initialize"
    headers = {
        "Authorization": f"Bearer {current_app.config['PAYSTACK_SECRET_KEY']}",
        "Content-Type": "application/json"
    }
    if callback_type == 'barorder':
        callback_url = url_for('paystack_barorder_callback', _external=True)
    else:
        callback_url = url_for('paystack_booking_callback', _external=True)
    payload = {
        "email": email,
        "amount": int(amount * 100),
        "reference": reference,
        "metadata": metadata or {},
        "callback_url": callback_url
    }
    app.logger.info(f"Initializing Paystack payment: {payload}")

    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        app.logger.info(f"Paystack response: {response.json()}")
        return response.json()
    except requests.exceptions.HTTPError as e:
        app.logger.error(f"Paystack HTTP error: {e.response.text}")
        return None
    except Exception as e:
        app.logger.error(f"Paystack initialization error: {str(e)}")
        return None
 

def assign_scheduled_cleaning():
    with app.app_context():
        try:
            # Only run at 8:00 AM and 4:00 PM
            now = datetime.now(NIGERIA_TZ)
            if not ((now.hour == 8 and now.minute == 0) or (now.hour == 16 and now.minute == 0)):
                return

            housekeepers = get_active_housekeepers()
            if not housekeepers:
                app.logger.warning("No active housekeepers available")
                return

            # Get dirty rooms
            dirty_rooms = Room.query.filter_by(cleaning_status='dirty').all()
            if not dirty_rooms:
                app.logger.info("No dirty rooms to clean")
                return

            # Calculate assignments per staff
            rooms_per_staff = max(1, len(dirty_rooms) // len(housekeepers))
            
            # Distribute rooms evenly
            for i, staff in enumerate(housekeepers):
                start_idx = i * rooms_per_staff
                end_idx = (i + 1) * rooms_per_staff
                
                # Handle last staff getting remaining rooms
                if i == len(housekeepers) - 1:
                    assigned_rooms = dirty_rooms[start_idx:]
                else:
                    assigned_rooms = dirty_rooms[start_idx:end_idx]
                
                for room in assigned_rooms:
                    # Set due time (2 hours for current shift)
                    due_time = now + timedelta(hours=2)
                    
                    assignment = CleaningAssignment(
                        room_id=room.id,
                        staff_id=staff.id,
                        due_by=due_time,
                        priority=2,  # Medium priority
                        status='pending'
                    )
                    db.session.add(assignment)
                    room.cleaning_status = 'assigned'
                    
                    # Create notification
                    notification = Notification(
                        user_id=staff.user_id,
                        title="New Cleaning Assignment",
                        message=f"Room {room.name} assigned to you",
                        category="assignment"
                    )
                    db.session.add(notification)
            
            db.session.commit()
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Scheduled cleaning error: {str(e)}")

def assign_immediate_cleaning(room_id):
    with app.app_context():
        try:
            room = Room.query.get(room_id)
            if not room or room.cleaning_status != 'dirty':
                return
                
            housekeepers = get_active_housekeepers()
            if not housekeepers:
                app.logger.warning("No active housekeepers for immediate cleaning")
                return
                
            # Find staff with fewest current assignments
            staff_assignments = {}
            for staff in housekeepers:
                count = CleaningAssignment.query.filter(
                    CleaningAssignment.staff_id == staff.id,
                    CleaningAssignment.status.in_(['pending', 'in_progress'])
                ).count()
                staff_assignments[staff.id] = count
                
            # Sort by assignment count (ascending)
            sorted_staff = sorted(housekeepers, key=lambda s: staff_assignments.get(s.id, 0))
            assigned_staff = sorted_staff[0]
            
            # Create assignment (due in 1 hour)
            assignment = CleaningAssignment(
                room_id=room.id,
                staff_id=assigned_staff.id,
                due_by=datetime.now(NIGERIA_TZ) + timedelta(hours=1),
                priority=1,  # High priority
                status='pending'
            )
            db.session.add(assignment)
            room.cleaning_status = 'assigned'
            
            # Create notification
            notification = Notification(
                user_id=assigned_staff.user_id,
                title="Immediate Cleaning Needed",
                message=f"Room {room.name} requires immediate cleaning",
                category="assignment"
            )
            db.session.add(notification)
            
            db.session.commit()
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Immediate assignment error: {str(e)}")


def role_required(allowed_roles):
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            if not any(current_user.has_role(role) for role in allowed_roles):
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/receptionist/confirm_checkout', methods=['POST'])
@role_required(['receptionist', 'super_admin'])
def confirm_checkout():
    room_number = request.form.get('room_number')
    booking_id = request.form.get('booking_id')
    otp = request.form.get('otp')
    
    if booking_id:
        booking = Booking.query.get(booking_id)
        if not booking:
            flash('Booking not found', 'error')
            return redirect(url_for('receptionist_dashboard'))
            
        room = booking.room
    elif room_number:
        room = Room.query.filter_by(name=room_number).first()
        if not room:
            flash('Invalid room number', 'error')
            return redirect(url_for('receptionist_dashboard'))
            
        booking = Booking.query.filter(
            Booking.room_id == room.id,
            Booking.check_in_status == 'Checked-in',
            Booking.checked_out == False
        ).order_by(Booking.check_out_date.desc()).first()
    else:
        flash('Missing room or booking information', 'error')
        return redirect(url_for('receptionist_dashboard'))
    
    if not booking:
        flash('No active booking found for this room', 'error')
        return redirect(url_for('receptionist_dashboard'))
    
    # Skip OTP verification if this is an automatic checkout
    if not booking.auto_checked_out:
        if not booking.checkout_otp or booking.checkout_otp != otp:
            flash('Invalid OTP code', 'error')
            return redirect(url_for('receptionist_dashboard'))
        
        now = datetime.now(NIGERIA_TZ)
        if booking.checkout_otp_expiry < now:
            flash('OTP has expired', 'error')
            return redirect(url_for('receptionist_dashboard'))
    
    # Process checkout
    booking.check_in_status = 'Checked-out'
    booking.checked_out = True
    booking.checked_out_at = now
    room.status = 'available'
    room.cleaning_status = 'dirty'
    
    # Assign immediate cleaning
    assign_immediate_cleaning(room.id)
    
    # Create notification
    notification = Notification(
        user_id=booking.user_id,
        title="Checkout Completed",
        message=f"You've successfully checked out of Room {room.name}",
        category="booking"
    )
    db.session.add(notification)
    
    db.session.commit()
    
    flash(f'Checkout confirmed for Room {room_number}!', 'success')
    return redirect(url_for('receptionist_dashboard'))


# ...other utility functions...
def auto_checkout_and_notifications():
    with app.app_context():
        now = datetime.now(NIGERIA_TZ)
        # Process automatic checkouts at 7:00 AM
        checkout_time = now.replace(hour=7, minute=0, second=0, microsecond=0)
        
        # Only run at 7:00 AM
        if now.hour == 7 and now.minute == 0:
            overdue_bookings = Booking.query.filter(
                Booking.check_out_date == now.date(),
                Booking.checked_out == False,
                Booking.check_in_status == 'Checked-in'
            ).all()
            
            for booking in overdue_bookings:
                # Update booking status
                booking.check_in_status = 'Checked-out'
                booking.checked_out = True
                booking.checked_out_at = now
                booking.auto_checked_out = True
                
                # Update room status
                booking.room.status = 'available'
                booking.room.cleaning_status = 'dirty'
                
                # Send rating request if not rated
                if not booking.is_rated:
                    send_rating_request(booking)
                
                # Create notification
                notification = Notification(
                    user_id=booking.user_id,
                    title="Automatic Checkout",
                    message=f"Your checkout for Room {booking.room.name} has been automatically processed",
                    category="booking"
                )
                db.session.add(notification)
                
            db.session.commit()

def verify_paystack_payment(reference):
    url = f"{current_app.config['PAYSTACK_BASE_URL']}/transaction/verify/{reference}"
    headers = {
        "Authorization": f"Bearer {current_app.config['PAYSTACK_SECRET_KEY']}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Paystack verification error: {e}")
        return None


def log_activity(title, description):
    activity = ActivityLog(
        title=title,
        description=description,
        initiator_id=current_user.id,
        timestamp=datetime.now(NIGERIA_TZ)
    )
    db.session.add(activity)
    db.session.commit()

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']
def convert_image_to_base64(image_path):
    try:
        with open(image_path, "rb") as image_file:
            encoded_string = base64.b64encode(image_file.read()).decode('utf-8')
            
            # Detect MIME type
            kind = filetype.guess(image_path)
            if not kind:
                return None  # Unknown file type
            
            mime_type = kind.mime
            return f"data:{mime_type};base64,{encoded_string}"
    except Exception as e:
        app.logger.error(f"Error converting image to base64: {e}")
        return None


def send_shift_reminders():
    with app.app_context():
        now = datetime.now(NIGERIA_TZ)
        # Notifications 10 minutes before shift
        upcoming_shifts = Shift.query.filter(
            Shift.start_time.between(now, now + timedelta(minutes=10)),
            Shift.notified == False
        ).all()
        
        for shift in upcoming_shifts:
            staff = Staff.query.get(shift.staff_id)
            message = f"Your {shift.shift_type} shift starts at {shift.start_time.strftime('%H:%M')}"
            send_email(
    staff.email,
    "Shift Reminder",
    message
)
            # Create notification
            notification = Notification(
                user_id=staff.user_id,
                title="Shift Reminder",
                message=message,
                category="attendance"
            )
            db.session.add(notification)
            shift.notified = True
        
        db.session.commit()
        


# CORRECTED SCHEDULER JOBS
def generate_shift_otps():
    with app.app_context():
        now = datetime.now(NIGERIA_TZ)
        ten_minutes_from_now = now + timedelta(minutes=10)
        
        # Check-in OTPs (for shifts starting in 10 minutes)
        upcoming_shifts = Shift.query.filter(
            Shift.start_time.between(now, ten_minutes_from_now),
            Shift.attendance_otp.is_(None)
        ).all()
        
        for shift in upcoming_shifts:
            otp = generate_otp(6)
            shift.attendance_otp = otp
            shift.otp_expiry = shift.start_time + timedelta(minutes=20)
            send_shift_otp(shift.staff, "checkin", otp, shift.start_time)
        
        # Check-out OTPs (for shifts ending in 10 minutes)
        upcoming_checkouts = Shift.query.filter(
            Shift.end_time.between(now, ten_minutes_from_now),
            Shift.checkout_otp.is_(None)
        ).all()
        
        for shift in upcoming_checkouts:
            otp = generate_otp(6)
            shift.checkout_otp = otp
            shift.checkout_otp_expiry = shift.end_time + timedelta(minutes=20)
            send_shift_otp(shift.staff, "checkout", otp, shift.end_time)
        
        db.session.commit()


# Utility Functions
def generate_shift_otp():
    """Generate a 6-digit numeric OTP"""
    return ''.join(random.choices('0123456789', k=6))

def generate_shift_otp_job():
    with app.app_context():
        now = datetime.now(NIGERIA_TZ)
        # 30 minutes before shift start/end
        threshold = now + timedelta(minutes=30)
        
        # Check-in OTPs
        upcoming_shifts = Shift.query.filter(
            Shift.start_time.between(now, threshold),
            Shift.attendance_otp.is_(None)
        ).all()
        
        for shift in upcoming_shifts:
            staff = Staff.query.get(shift.staff_id)
            if staff and staff.is_active:
                otp = generate_otp(6)
                shift.attendance_otp = otp
                shift.otp_expiry = shift.start_time + timedelta(minutes=20)
                # Pass all 4 arguments
                send_shift_otp(staff, "checkin", otp, shift.start_time)
        
        # Check-out OTPs
        upcoming_checkouts = Shift.query.filter(
            Shift.end_time.between(now, threshold),
            Shift.checkout_otp.is_(None)
        ).all()
        
        for shift in upcoming_checkouts:
            staff = Staff.query.get(shift.staff_id)
            if staff and staff.is_active:
                otp = generate_otp(6)
                shift.checkout_otp = otp
                shift.checkout_otp_expiry = shift.end_time + timedelta(minutes=20)
                # Pass all 4 arguments
                send_shift_otp(staff, "checkout", otp, shift.end_time)
        
        db.session.commit()


def send_shift_otp(staff, action_type, otp, action_time):
    action_name = "Check-in" if action_type == "checkin" else "Check-out"
    subject = f"Shift {action_name} OTP - Hotel Marlin"
    body = (f"Your OTP for {action_name} is: {otp}\n\n"
            f"Action time: {action_time.strftime('%H:%M')}\n"
            "This OTP expires in 20 minutes.")
    
    # Email notification
    send_email(staff.email, subject, body)
    
    # App notification
    notification = Notification(
        user_id=staff.user_id,
        title=f"Shift {action_name} OTP",
        message=f"Your OTP: {otp}",
        category="attendance"
    )
    db.session.add(notification)
    db.session.commit()


# In app.py - update handle_missed_shifts function
def handle_missed_shifts():
    with app.app_context():
        now = datetime.now(NIGERIA_TZ)
        threshold = now - timedelta(minutes=20)
        
        missed_shifts = Shift.query.filter(
            Shift.start_time <= threshold,
            Shift.attendance_status == 'pending'
        ).all()
        
        for shift in missed_shifts:
            shift.attendance_status = 'absent'
            
            # Create attendance record with minimal required fields
            attendance = Attendance(
                staff_id=shift.staff_id,
                date=shift.shift_date,
                clock_in_time=None,  # Explicitly set to None
                status='absent'  # Add status field
            )
            db.session.add(attendance)
            
            notification = Notification(
                user_id=Staff.query.get(shift.staff_id).user_id,
                title="Missed Shift",
                message=f"You missed your {shift.shift_type} shift on {shift.shift_date}",
                category="attendance"
            )
            db.session.add(notification)
        
        db.session.commit()

def send_shift_otp_job():
    with app.app_context():
        now = datetime.now(NIGERIA_TZ)
        ten_minutes_from_now = now + timedelta(minutes=10)
        
        # Find shifts starting in 10 minutes that haven't had OTP sent
        upcoming_shifts = Shift.query.filter(
            Shift.start_time.between(now, ten_minutes_from_now),
            Shift.attendance_otp.is_(None)
        ).all()
        
        for shift in upcoming_shifts:
            staff = Staff.query.get(shift.staff_id)
            if staff and staff.is_active:
                # Generate OTP
                otp = generate_shift_otp()
                shift.attendance_otp = otp
                shift.otp_generated_at = now
                shift.otp_expiry = shift.start_time + timedelta(minutes=20)  # 20 min grace period
                
                # Send OTP through all channels
                send_shift_otp(staff, shift, otp)
                
                app.logger.info(f"Sent OTP {otp} for shift {shift.id} to staff {staff.id}")
        
        db.session.commit()

def check_booking_expiry():
    with app.app_context():
        now = datetime.now(NIGERIA_TZ)
        expired_bookings = Booking.query.filter(
            Booking.otp_expiry < now,
            Booking.payment_status == 'pending',
            Booking.check_in_status == 'Pending'
        ).all()
        
        for booking in expired_bookings:
            booking.check_in_status = 'Expired'
            booking.room.status = 'available'
            db.session.commit()
def cleanup_expired_bookings():
    with app.app_context():
        try:
            # Delete bookings that expired more than 1 hour ago
            expiry_threshold = datetime.now(NIGERIA_TZ) - timedelta(hours=1)
            
            expired_bookings = Booking.query.filter(
                Booking.otp_expiry < expiry_threshold,
                Booking.payment_status == 'pending'
            ).all()
            
            for booking in expired_bookings:
                # Release the room first
                room = Room.query.get(booking.room_id)
                if room:
                    room.status = 'available'
                
                # Delete associated payment record
                Payment.query.filter_by(booking_id=booking.id).delete()
                
                # Finally delete the booking
                db.session.delete(booking)
            
            db.session.commit()
            app.logger.info(f"Cleaned up {len(expired_bookings)} expired bookings")
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error cleaning expired bookings: {str(e)}")

@app.route('/booking/receipt/<int:booking_id>')
@login_required
def booking_receipt(booking_id):
    # Get booking details
    booking = Booking.query.get_or_404(booking_id)

    # Authorization check
    if booking.user_id != current_user.id and not any(role.name in ['admin', 'super_admin', 'staff'] for role in current_user.roles):
        abort(403)

    # 80mm receipt size: width ~227 points, height can be long (e.g. 600)
    RECEIPT_WIDTH = 227  # 80mm in points
    RECEIPT_HEIGHT = 600  # Adjust as needed for content

    buffer = BytesIO()
    from reportlab.pdfgen import canvas
    p = canvas.Canvas(buffer, pagesize=(RECEIPT_WIDTH, RECEIPT_HEIGHT))
    width, height = RECEIPT_WIDTH, RECEIPT_HEIGHT

    # Styling variables for receipt
    normal_font = "Courier"
    bold_font = "Courier-Bold"
    font_size = 9
    header_size = 12
    line_height = 13
    margin = 10
    top = height - margin

    # Header
    p.setFont(bold_font, header_size)
    p.drawCentredString(width/2, top, "MARLIN HOTEL AND SUITES")
    top -= line_height
    p.setFont(normal_font, font_size)
    p.drawCentredString(width/2, top, "91 Road, Festac Extension, Abule Ado")
    top -= line_height
    p.drawCentredString(width/2, top, "Lagos, Nigeria")
    top -= line_height
    p.drawCentredString(width/2, top, "Tel: +234 916 455 6280")
    top -= line_height
    p.drawCentredString(width/2, top, "marlinhotel007@gmail.com")
    top -= line_height

    # Divider
    p.line(margin, top, width - margin, top)
    top -= line_height

    # Receipt Title
    p.setFont(bold_font, header_size)
    p.drawCentredString(width/2, top, "BOOKING RECEIPT")
    top -= line_height

    # Divider
    p.line(margin, top, width - margin, top)
    top -= line_height

    # Booking Details
    p.setFont(bold_font, font_size)
    p.drawString(margin, top, "Booking Details:")
    top -= line_height

    p.setFont(normal_font, font_size)
    details = [
        ("Receipt No:", f"BK-{booking.id:05d}"),
        ("Date:", datetime.now(NIGERIA_TZ).strftime("%d-%b-%Y %H:%M")),
        ("Guest:", booking.user.username),
        ("Room:", booking.room.name),
        ("Room Type:", booking.room.room_type),
        ("Check-in:", booking.check_in_date.strftime("%d %b %Y, %H:%M")),
        ("Check-out:", booking.check_out_date.strftime("%d %b %Y, %H:%M")),
        ("Nights:", str(max(1, (booking.check_out_date.date() - booking.check_in_date.date()).days))),
        ("Rate/Night:", f"₦{booking.room.price:,.2f}"),
    ]
    for label, value in details:
        p.drawString(margin, top, f"{label} {value}")
        top -= line_height

    # Divider
    p.line(margin, top, width - margin, top)
    top -= line_height

    # Payment Details
    p.setFont(bold_font, font_size)
    p.drawString(margin, top, "Payment Details:")
    top -= line_height

    p.setFont(normal_font, font_size)
    p.drawString(margin, top, f"Room Charges: ₦{booking.total_amount:,.2f}")
    top -= line_height

    p.setFont(bold_font, font_size + 1)
    p.drawString(margin, top, f"TOTAL PAID: ₦{booking.total_amount:,.2f}")
    top -= line_height * 2

    # Payment status
    p.setFont(normal_font, font_size)
    p.drawString(margin, top, f"Payment status: {booking.payment_status or 'Paystack'}")
    top -= line_height

    # Divider
    p.line(margin, top, width - margin, top)
    top -= line_height

    # Footer
    p.setFont(normal_font, font_size)
    notes = [
        "Thank you for choosing Marlin Hotel & Suites!",
        "For inquiries: marlinhotel007@gmail.com",
        "Check-out time: 12:00 PM",
        f"Receipt No: BK-{booking.id:05d}"
    ]
    for note in notes:
        p.drawCentredString(width/2, top, note)
        top -= line_height

    # Finalize PDF
    p.showPage()
    p.save()

    pdf = buffer.getvalue()
    buffer.close()

    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'inline; filename=booking_receipt_{booking_id}.pdf'
    return response

# New helper function
# In staff registration
def assign_housekeeping_shifts(staff):
    try:
        # Assign shifts with Nigeria timezone (UTC+1)
        nigeria_tz = pytz.timezone('Africa/Lagos')
        base_date = datetime.utcnow().date()
        
        for day in range(7):
            shift_date = base_date + timedelta(days=day)
            
            # Day shift: 8:30 AM - 4:00 PM Nigeria time (7:30-15:00 UTC)
            day_shift = Shift(
                staff_id=staff.id,
                shift_type='Day',
                start_time=nigeria_tz.localize(datetime.combine(shift_date, time(7, 30))).astimezone(timezone.utc),
                end_time=nigeria_tz.localize(datetime.combine(shift_date, time(15, 0))).astimezone(timezone.utc),
                position='Housekeeper'
            )
            
            # Night shift: 4:00 PM - 12:00 AM Nigeria time (15:00-23:00 UTC)
            night_shift = Shift(
                staff_id=staff.id,
                shift_type='Night',
                start_time=nigeria_tz.localize(datetime.combine(shift_date, time(15, 0))).astimezone(timezone.utc),
                end_time=nigeria_tz.localize(datetime.combine(shift_date, time(23, 0))).astimezone(timezone.utc),
                position='Housekeeper'
            )
            
            db.session.add(day_shift)
            db.session.add(night_shift)
        
        db.session.commit()
    except Exception as e:
        app.logger.error(f"Shift assignment error: {str(e)}")



@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id)) 

def get_recent_expenses(limit=5):
    return Expense.query.order_by(Expense.date.desc()).limit(limit).all()

@app.route('/order/receipt/<int:order_id>')
def order_receipt(order_id):
    order = BarOrder.query.get_or_404(order_id)
    
    buffer = BytesIO()
    p = canvas.Canvas(buffer)
    
    # Create PDF content
    p.drawString(100, 800, f"Hotel Marlin Receipt - Order #{order.id}")
    y = 780
    for item in order.order_items:
        p.drawString(100, y, f"{item.quantity}x {item.item.name} @ {item.price} each")
        y -= 20
    p.drawString(100, y-40, f"Total: {order.total_amount}")
    
    p.showPage()
    p.save()
    
    pdf = buffer.getvalue()
    buffer.close()
    
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=receipt_{order_id}.pdf'
    return response


from flask import g

# app.py
@app.context_processor
def inject_notifications():
    if current_user.is_authenticated:
        notifications = Notification.query.filter_by(
            user_id=current_user.id
        ).order_by(Notification.created_at.desc()).limit(3).all()
        return dict(user_notifications=notifications)  # Changed to user_notifications
    return dict(user_notifications=[])


@app.route('/order/receipt/html/<int:order_id>')
@login_required
def order_receipt_html(order_id):
    order = BarOrder.query.get_or_404(order_id)
    auto_print = request.args.get('auto_print', '0') == '1'
    return render_template('receipt.html', order=order, auto_print=auto_print)

@app.route('/search')
@admin_required
def admin_search():
    query = request.args.get('q', '').strip()
    filter_type = request.args.get('type', 'all').lower()
    
    results = {
        'room_results': [],
        'staff_results': [],
        'booking_results': [],
        'user_results': []
    }
    
    # Apply filters based on type
    if filter_type in ['all', 'rooms']:
        results['room_results'] = Room.query.filter(
            Room.name.ilike(f'%{query}%')
        ).limit(5).all()
    
    if filter_type in ['all', 'staff']:
        results['staff_results'] = Staff.query.filter(
            or_(
                Staff.first_name.ilike(f'%{query}%'),
                Staff.last_name.ilike(f'%{query}%'),
                Staff.position.ilike(f'%{query}%'),
                Staff.email.ilike(f'%{query}%')
            )
        ).limit(5).all()
    
    if filter_type in ['all', 'bookings']:
        results['booking_results'] = Booking.query.filter(
            or_(
                Booking.id.ilike(f'%{query}%'),
                Booking.user.has(User.username.ilike(f'%{query}%'))
            )
        ).limit(5).all()
    
    if filter_type in ['all', 'guests']:
        results['user_results'] = User.query.filter(
            or_(
                User.username.ilike(f'%{query}%'),
                User.email.ilike(f'%{query}%')
            )
        ).limit(5).all()
    
    total_results = sum(len(r) for r in results.values())
    
    return render_template('admin_search.html', 
                         query=query,
                         filter_type=filter_type,
                         results=results,
                         total_results=total_results,
                         search_time=0.1)
# Update SHIFT_CONFIG at the top of app.py
# CORRECTED shift configuration (8 AM to 8 PM shifts)
SHIFT_CONFIG = {
    'Day': {'start': '08:00', 'end': '20:00'},      # 8 AM to 8 PM
    'Night': {'start': '20:00', 'end': '08:00'},    # 8 PM to 8 AM next day
    'shift_rotation_days': 1,  # Rotate daily
    'positions': [
        'Front Desk Agent', 'Receptionist', 'Concierge', 'Housekeeper',
        'Bellhop', 'Night Auditor', 'Maintenance', 'Security',
        'Manager', 'General Manager', 'Restaurant Staff', 'Chef',
        'Waiter', 'Bartender', 'Porter', 'Valet', 'Laundry Staff',
        'Event Coordinator', 'Spa Staff'
    ]
}
app.config['SHIFT_CONFIG'] = SHIFT_CONFIG  # Add to app config

# In app.py - update generate_rotational_shifts function
# CORRECTED generate_rotational_shifts function


# Shift Management
@app.route('/admin/shifts/generate', methods=['POST', 'GET'])
@admin_required
def generate_rotational_shifts():
    with app.app_context():
        try:
            shift_config = app.config['SHIFT_CONFIG']
            Shift.query.delete()
            
            positions = shift_config['positions']
            total_shifts_created = 0
            base_date = datetime.now(NIGERIA_TZ).date()
            
            for position in positions:
                staff_members = Staff.query.filter(
                    Staff.position == position,
                    Staff.is_active == True
                ).all()
                
                if not staff_members:
                    continue
                    
                groups = [staff_members[:len(staff_members)//2], staff_members[len(staff_members)//2:]]
                
                for day in range(7):
                    shift_date = base_date + timedelta(days=day)
                    rotation_index = day % 2
                    shift_types = ['Day', 'Night'] if rotation_index == 0 else ['Night', 'Day']
                    
                    for group_idx, group in enumerate(groups):
                        if group_idx >= len(shift_types):
                            continue
                            
                        shift_type = shift_types[group_idx]
                        config = shift_config[shift_type]
                        
                        start_time = datetime.strptime(config['start'], '%H:%M').time()
                        end_time = datetime.strptime(config['end'], '%H:%M').time()
                        
                        if shift_type == 'Night' and end_time < start_time:
                            shift_start = NIGERIA_TZ.localize(datetime.combine(shift_date, start_time))
                            shift_end = NIGERIA_TZ.localize(datetime.combine(shift_date + timedelta(days=1), end_time))
                        else:
                            shift_start = NIGERIA_TZ.localize(datetime.combine(shift_date, start_time))
                            shift_end = NIGERIA_TZ.localize(datetime.combine(shift_date, end_time))
                            
                        for staff in group:
                            new_shift = Shift(
                                staff_id=staff.id,
                                shift_type=shift_type,
                                start_time=shift_start,
                                end_time=shift_end,
                                shift_date=shift_date,
                                position=position
                            )
                            db.session.add(new_shift)
                            total_shifts_created += 1

            db.session.commit()
            flash(f'Shifts generated! Created {total_shifts_created} shifts', 'success')
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Shift generation error: {str(e)}")
            flash(f'Shift generation failed: {str(e)}', 'error')
        return redirect(url_for('hr_dashboard'))
    

def assign_dirty_rooms():
    with app.app_context():
        try:
            now = datetime.now(NIGERIA_TZ)
            app.logger.info(f"Running room assignment scheduler at {now}")
            
            # 1. Get all dirty rooms
            dirty_rooms = Room.query.filter_by(cleaning_status='dirty').all()
            if not dirty_rooms:
                app.logger.info("No dirty rooms found")
                return
                
            app.logger.info(f"Found {len(dirty_rooms)} dirty rooms")
            
            # 2. Find active housekeeping staff (on current shift)
            housekeepers = Staff.query.filter(
                Staff.position == 'Housekeeper',
                Staff.is_active == True,
                Staff.shifts.any(and_(
                    Shift.start_time <= now,
                    Shift.end_time >= now
                ))
            ).all()
            
            if not housekeepers:
                app.logger.warning("No active housekeepers found")
                return
                
            app.logger.info(f"Found {len(housekeepers)} active housekeepers")
            
            # 3. Assign rooms to staff with fewest assignments
            for room in dirty_rooms:
                # Find staff with fewest assignments
                assignments_count = {}
                for staff in housekeepers:
                    count = CleaningAssignment.query.filter(
                        CleaningAssignment.staff_id == staff.id,
                        CleaningAssignment.status.in_(['pending', 'in_progress'])
                    ).count()
                    assignments_count[staff.id] = count
                
                # Sort staff by assignment count
                sorted_staff = sorted(housekeepers, key=lambda s: assignments_count.get(s.id, 0))
                staff = sorted_staff[0]
                
                # Create assignment
                assignment = CleaningAssignment(
                    room_id=room.id,
                    staff_id=staff.id,
                    due_by=now + timedelta(minutes=30),  # Due in 30 minutes
                    priority=1,
                    status='pending'
                )
                db.session.add(assignment)
                
                # Update room status
                room.cleaning_status = 'assigned'
                
                # Create notification
                notification = Notification(
                    user_id=staff.user_id,
                    title="New Cleaning Assignment",
                    message=f"Room {room.name} needs cleaning",
                    category="assignment"
                )
                db.session.add(notification)
                
                app.logger.info(f"Assigned Room {room.name} to {staff.first_name}")
            
            db.session.commit()
            app.logger.info(f"Assigned {len(dirty_rooms)} rooms successfully")
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Room assignment error: {str(e)}")

@app.route('/admin/shifts/clear', methods=['POST'])
@admin_required
def clear_shifts():
    try:
        Shift.query.delete()
        db.session.commit()
        flash('All shifts cleared', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error clearing shifts: {str(e)}")
        flash('Failed to clear shifts', 'error')
    return redirect(url_for('hr_dashboard'))

# Attendance Verification
@app.route('/verify-checkin-otp', methods=['POST'])
@role_required(['hr', 'super_admin'])
def verify_checkin_otp():
    staff_id = request.form.get('staff_id')
    otp = request.form.get('otp')
    
    staff = Staff.query.get(staff_id)
    if not staff:
        flash('Staff not found', 'error')
        return redirect(url_for('hr_dashboard'))
    
    now = datetime.now(NIGERIA_TZ)
    shift = Shift.query.filter(
        Shift.staff_id == staff.id,
        Shift.attendance_otp == otp,
        Shift.otp_expiry >= now
    ).first()

    if shift:
        attendance = Attendance(
            staff_id=staff.id,
            shift_id=shift.id,
            clock_in_time=now,
            date=now.date(),
            status='on-time' if now <= shift.start_time else 'late'
        )
        db.session.add(attendance)
        shift.attendance_status = attendance.status
        db.session.commit()
        flash(f'Check-in recorded for {staff.first_name}', 'success')
    else:
        flash('Invalid OTP or expired', 'error')
    
    return redirect(url_for('hr_dashboard'))

@app.route('/verify-checkout-otp', methods=['POST'])
@role_required(['hr', 'super_admin'])
def verify_checkout_otp():
    staff_id = request.form.get('staff_id')
    otp = request.form.get('otp')
    
    staff = Staff.query.get(staff_id)
    if not staff:
        flash('Staff not found', 'error')
        return redirect(url_for('hr_dashboard'))
    
    now = datetime.now(NIGERIA_TZ)
    shift = Shift.query.filter(
        Shift.staff_id == staff.id,
        Shift.checkout_otp == otp,
        Shift.checkout_otp_expiry >= now
    ).first()

    if shift:
        attendance = Attendance.query.filter(
            Attendance.staff_id == staff.id,
            Attendance.shift_id == shift.id,
            Attendance.clock_out_time.is_(None)
        ).first()
        
        if attendance:
            attendance.clock_out_time = now
            shift.attendance_status = 'completed'
            db.session.commit()
            flash(f'Check-out recorded for {staff.first_name}', 'success')
        else:
            flash('No active attendance record', 'error')
    else:
        flash('Invalid OTP or expired', 'error')
    
    return redirect(url_for('hr_dashboard'))



def generate_daily_reports():
    with app.app_context():
        try:
            # Get yesterday's date
            yesterday = datetime.now(NIGERIA_TZ).date() - timedelta(days=1)
            
            # Create report data
            bookings = Booking.query.filter(
                func.date(Booking.created_at) == yesterday
            ).count()
            
            revenue = db.session.query(func.sum(Payment.amount)).filter(
                func.date(Payment.created_at) == yesterday
            ).scalar() or 0
            
            # Create report object
            report = Report(
                report_type='daily',
                parameters={
                    'date': yesterday.isoformat(),
                    'bookings': bookings,
                    'revenue': revenue
                },
                generated_by=0  # System-generated
            )
            db.session.add(report)
            db.session.commit()
            
            app.logger.info(f"Generated daily report for {yesterday}")
        except Exception as e:
            app.logger.error(f"Daily report generation error: {str(e)}")



# utils.py


def assign_housekeeping_tasks():
    with app.app_context():
        try:
            now = datetime.now(NIGERIA_TZ)
            # Only run at 8:30 AM and 4:00 PM
            if not ((now.hour == 8 and now.minute == 30) or (now.hour == 16 and now.minute == 0)):
                return
                
            # Find active housekeeping staff
            housekeepers = Staff.query.filter(
                Staff.position == 'Housekeeper',
                Staff.is_active == True,
                Staff.shifts.any(and_(
                    Shift.start_time <= now,
                    Shift.end_time >= now
                ))
            ).all()
            
            if not housekeepers:
                app.logger.warning("No active housekeepers available")
                return
                
            # Get dirty rooms
            rooms_to_clean = Room.query.filter(Room.cleaning_status == 'dirty').all()
            
            if not rooms_to_clean:
                app.logger.info("No rooms need cleaning")
                return
                
            # Assign rooms
            rooms_per_staff = max(1, len(rooms_to_clean) // len(housekeepers))
            
            for i, staff in enumerate(housekeepers):
                start_idx = i * rooms_per_staff
                end_idx = (i + 1) * rooms_per_staff
                assigned_rooms = rooms_to_clean[start_idx:end_idx] if i < len(housekeepers) - 1 else rooms_to_clean[start_idx:]
                
                for room in assigned_rooms:
                    due_time = now.replace(hour=12, minute=0) if now.hour == 8 else now.replace(hour=20, minute=0)
                    assignment = CleaningAssignment(
                        room_id=room.id,
                        staff_id=staff.id,
                        due_by=due_time,
                        priority=1
                    )
                    db.session.add(assignment)
                    room.cleaning_status = 'assigned'
                    
                    # Notification
                    notification = Notification(
                        user_id=staff.user_id,
                        title="New Cleaning Assignment",
                        message=f"Room {room.name} assigned to you",
                        category="assignment"
                    )
                    db.session.add(notification)
            
            db.session.commit()
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Housekeeping assignment error: {str(e)}")

def assign_immediate_cleaning(room_id):
    with app.app_context():
        room = Room.query.get(room_id)
        if room.cleaning_status != 'dirty':
            return
            
        now = datetime.now(NIGERIA_TZ)
        housekeepers = Staff.query.filter(
            Staff.position == 'Housekeeper',
            Staff.is_active == True,
            Staff.shifts.any(and_(
                Shift.start_time <= now,
                Shift.end_time >= now
            ))
        ).all()
        
        if not housekeepers:
            return
            
        # Find staff with fewest assignments
        assignments_count = defaultdict(int)
        for staff in housekeepers:
            count = CleaningAssignment.query.filter(
                CleaningAssignment.staff_id == staff.id,
                CleaningAssignment.status.in_(['pending', 'in_progress'])
            ).count()
            assignments_count[staff.id] = count
            
        # Sort by assignment count
        sorted_staff = sorted(housekeepers, key=lambda s: assignments_count[s.id])
        staff = sorted_staff[0]
        
        assignment = CleaningAssignment(
            room_id=room_id,
            staff_id=staff.id,
            due_by=now + timedelta(hours=1),
            priority=1
        )
        db.session.add(assignment)
        room.cleaning_status = 'assigned'
        db.session.commit()
        
        # Notification
        notification = Notification(
            user_id=staff.user_id,
            title="Immediate Cleaning Assignment",
            message=f"Room {room.name} needs immediate cleaning",
            category="assignment"
        )
        db.session.add(notification)
        db.session.commit()


# Cleaning Assignment Routes
@app.route('/staff/cleaning-tasks')
@role_required(['staff'])
def cleaning_tasks():
    staff = Staff.query.filter_by(user_id=current_user.id).first()
    if not staff:
        flash('Staff profile not found', 'error')
        return redirect(url_for('staff_dashboard'))
    
    tasks = CleaningAssignment.query.filter_by(
        staff_id=staff.id,
        status='pending'
    ).order_by(CleaningAssignment.priority.asc()).all()
    
    # Update this in the cleaning_tasks route
    in_progress = CleaningAssignment.query.filter_by(
        staff_id=staff.id,
        status='in_progress'
    ).options(db.joinedload(CleaningAssignment.cleaning_log)).first()
        
    return render_template('cleaning_tasks.html', 
                         tasks=tasks,
                         in_progress=in_progress)


# Add this route to app.py in the "Cleaning Assignment Routes" section
@app.route('/staff/assignments')
@role_required(['staff', 'super_admin', 'housekeeping_supervisor'])
def staff_assignments():
    # Get assignments with room, staff, and cleaning log details
    assignments = CleaningAssignment.query.options(
        db.joinedload(CleaningAssignment.room),
        db.joinedload(CleaningAssignment.staff),
        db.joinedload(CleaningAssignment.cleaning_log)  # Changed from 'logs' to 'cleaning_log'
    ).order_by(
        CleaningAssignment.priority.asc(),
        CleaningAssignment.due_by.asc()
    ).all()
    
    return render_template('staff_assignments.html', assignments=assignments)


# Add this route to handle assignment completion
@app.route('/staff/assignments/complete/<int:assignment_id>', methods=['POST'])
@role_required(['staff'])
def complete_assignments(assignment_id):
    assignment = CleaningAssignment.query.get_or_404(assignment_id)
    
    # Authorization
    if assignment.staff.user_id != current_user.id:
        abort(403)
    
    # Update task
    assignment.status = 'completed'
    assignment.completed_at = datetime.now(NIGERIA_TZ)
    
    # Update room
    assignment.room.cleaning_status = 'clean'
    assignment.room.last_cleaned = datetime.now(NIGERIA_TZ)
    
    # Create cleaning log
    log = CleaningLog(
        assignment_id=assignment.id,
        staff_id=assignment.staff_id,
        start_time=datetime.now(NIGERIA_TZ) - timedelta(minutes=30),  # Assume 30 min duration
        end_time=datetime.now(NIGERIA_TZ),
        status='completed',
        notes=request.form.get('notes', '')
    )
    db.session.add(log)
    db.session.commit()
    
    flash('Cleaning task completed!', 'success')
    return redirect(url_for('staff_assignments'))


@app.route('/staff/start-cleaning/<int:task_id>', methods=['POST', 'GET'])
@role_required(['staff'])
def start_cleaning(task_id):
    task = CleaningAssignment.query.get_or_404(task_id)
    
    # Update task status
    task.status = 'in_progress'
    
    # Create cleaning log
    log = CleaningLog(
        assignment_id=task.id,
        staff_id=task.staff_id,
        start_time=datetime.now(NIGERIA_TZ),
        status='in_progress'
    )
    db.session.add(log)
    db.session.commit()
    
    flash(f'Started cleaning room {task.room.name}', 'success')
    return redirect(url_for('cleaning_tasks'))



@app.route('/staff/complete-cleaning/<int:task_id>', methods=['POST'])
@role_required(['staff'])
def complete_cleaning(task_id):
    task = CleaningAssignment.query.get_or_404(task_id)
    task.status = 'completed'
    task.completed_at = datetime.now(NIGERIA_TZ)  # Set completion time
    
    # Authorization
    if task.staff.user_id != current_user.id:
        abort(403)
    
    # Update task
    task.status = 'completed'
    task.completed_at = datetime.now(NIGERIA_TZ)
    
    # Update room
    task.room.cleaning_status = 'clean'
    task.room.last_cleaned = datetime.now(NIGERIA_TZ)
    
    # Create cleaning log
    log = CleaningLog(
        assignment_id=task.id,
        staff_id=task.staff_id,
        start_time=datetime.now(NIGERIA_TZ) - timedelta(minutes=30),  # Assume 30 min duration
        end_time=datetime.now(NIGERIA_TZ),
        status='completed',
        notes=request.form.get('notes', '')
    )
    db.session.add(log)
    db.session.commit()
    
    flash('Cleaning task completed!', 'success')
    return redirect(url_for('staff_assignments'))


@app.route('/staff/skip-cleaning/<int:task_id>', methods=['POST'])
@role_required(['staff'])
def skip_cleaning(task_id):
    task = CleaningAssignment.query.get_or_404(task_id)
    log = CleaningLog.query.filter_by(assignment_id=task.id).first()
    
    if not log:
        flash('Cleaning log not found', 'error')
        return redirect(url_for('cleaning_tasks'))
    
    # Update task and log
    task.status = 'completed'
    log.end_time = datetime.now(NIGERIA_TZ)
    log.status = 'skipped'
    log.notes = request.form.get('notes', '') or 'Skipped by staff'
    
    # Room remains dirty
    task.room.cleaning_status = 'needs_attention'
    
    db.session.commit()
    
    flash(f'Marked room {task.room.name} as skipped', 'warning')
    return redirect(url_for('cleaning_tasks'))



def check_shift_notifications():
    with app.app_context():
        now = datetime.now()
        # Notifications 10 minutes before shift
        upcoming_shifts = Shift.query.filter(
            Shift.start_time.between(now, now + timedelta(minutes=10)),
            Shift.notified == False
        ).all()
        
        for shift in upcoming_shifts:
            staff = Staff.query.get(shift.staff_id)
            message = f"Your {shift.shift_type} shift starts at {shift.start_time.strftime('%H:%M')}"
            Notification.send_shift_notification(staff.user_id, message)
            shift.notified = True
        
        # Reminder 10 minutes before shift end
        ending_shifts = Shift.query.filter(
            Shift.end_time.between(now, now + timedelta(minutes=10)),
            Shift.reminder_sent == False
        ).all()
        
        for shift in ending_shifts:
            staff = Staff.query.get(shift.staff_id)
            message = f"Your shift ends at {shift.end_time.strftime('%H:%M')}"
            Notification.send_shift_notification(staff.user_id, message)
            shift.reminder_sent = True
        
        db.session.commit()

def update_overdue_bookings_and_rooms():
    with app.app_context():
        try:
            now = datetime.now(NIGERIA_TZ)
            
            # 1. Update overdue bookings that should be checked out
            overdue_bookings = Booking.query.filter(
                Booking.check_out_date <= now,
                Booking.checked_out == False
            ).all()
            
            for booking in overdue_bookings:
                booking.check_in_status = 'Checked-out'
                booking.checked_out = True
                booking.checked_out_at = now
                
                # Update room status
                room = Room.query.get(booking.room_id)
                if room:
                    room.status = 'available'
                    room.cleaning_status = 'dirty'
                    room.last_occupied = now.date()
            
            # 2. Release rooms from pending bookings that expired
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
            app.logger.info(f"Updated {len(overdue_bookings)} overdue bookings and {len(expired_bookings)} expired bookings")
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error updating overdue bookings: {str(e)}")


def auto_checkout_overdue_bookings():
    with app.app_context():
        now = datetime.now(NIGERIA_TZ)
        # Only run at 12:00 PM Nigeria time
        if now.hour == 12 and now.minute == 0:
            # Find bookings that should have checked out by today at 12 PM
            check_out_time = now.replace(hour=12, minute=0, second=0, microsecond=0)
            
            overdue_bookings = Booking.query.filter(
                Booking.check_out_date <= check_out_time,
                Booking.checked_out == False,
                Booking.check_in_status == 'Checked-in'
            ).all()
            
            for booking in overdue_bookings:
                # Update booking status
                booking.check_in_status = 'Checked-out'
                booking.checked_out = True
                booking.checked_out_at = now
                booking.auto_checked_out = True
                
                # Update room status
                booking.room.status = 'available'
                booking.room.cleaning_status = 'dirty'
                
                # Create notification
                notification = Notification(
                    user_id=booking.user_id,
                    title="Automatic Checkout",
                    message=f"You've been automatically checked out of Room {booking.room.name}",
                    category="booking"
                )
                db.session.add(notification)
                
                # Log activity
                log_activity(
                    "Auto Checkout",
                    f"Booking {booking.id} automatically checked out of room {booking.room.name}"
                )
            
            db.session.commit()
            app.logger.info(f"Processed {len(overdue_bookings)} automatic checkouts")


def send_checkout_reminders():
    with app.app_context():
        now = datetime.now(NIGERIA_TZ)
        # Run at 11:50 AM daily (10 minutes before checkout)
        if now.hour == 11 and now.minute == 50:
            # Get bookings checking out today
            today_date = now.date()
            upcoming_checkouts = Booking.query.filter(
                Booking.check_out_date == today_date,
                Booking.checked_out == False,
                Booking.check_in_status == 'Checked-in'
            ).all()
            
            for booking in upcoming_checkouts:
                # Send email reminder
                send_email(
                    to_email=booking.user.email,
                    subject="Upcoming Checkout Reminder",
                    body=f"""Your checkout for Room {booking.room.name} is scheduled for 12:00 PM today.
Please prepare to vacate the room."""
                )
                
                # Create notification
                notification = Notification(
                    user_id=booking.user_id,
                    title="Checkout Reminder",
                    message=f"Checkout for Room {booking.room.name} in 10 minutes (12:00 PM)",
                    category="booking"
                )
                db.session.add(notification)
            
            db.session.commit()
            app.logger.info(f"Sent {len(upcoming_checkouts)} checkout reminders")


def check_missed_checkouts():
    with app.app_context():
        now = datetime.now(NIGERIA_TZ)
        # Check every 30 minutes for bookings that should have been checked out
        overdue_bookings = Booking.query.filter(
            Booking.check_out_date <= now,
            Booking.checked_out == False,
            Booking.check_in_status == 'Checked-in'
        ).all()
        
        if overdue_bookings:
            app.logger.info(f"Found {len(overdue_bookings)} missed checkouts, processing now")
            
        for booking in overdue_bookings:
            # Update booking status
            booking.check_in_status = 'Checked-out'
            booking.checked_out = True
            booking.checked_out_at = now
            booking.auto_checked_out = True
            
            # Update room status
            booking.room.status = 'available'
            booking.room.cleaning_status = 'dirty'
            
            # Create notification
            notification = Notification(
                user_id=booking.user_id,
                title="Late Checkout Processed",
                message=f"Your late checkout for Room {booking.room.name} has been processed",
                category="booking"
            )
            db.session.add(notification)
            
            # No need for OTP verification for automatic checkouts
            # Room is immediately marked as dirty for cleaning
            
        db.session.commit()

def cleanup_pending_payments():
    with app.app_context():
        try:
            # Delete payments pending for more than 30 minutes
            threshold = datetime.now(NIGERIA_TZ) - timedelta(minutes=30)
            
            pending_payments = Payment.query.filter(
                Payment.status == 'pending',
                Payment.created_at < threshold
            ).all()
            
            for payment in pending_payments:
                # Get booking using booking_id instead of direct relationship
                booking = Booking.query.get(payment.booking_id)
                
                # Release associated room if exists
                if booking and booking.room:
                    booking.room.status = 'available'
                db.session.delete(payment)
            
            db.session.commit()
            app.logger.info(f"Cleaned up {len(pending_payments)} pending payments")
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error cleaning pending payments: {str(e)}")
# Initialize scheduler
scheduler = BackgroundScheduler()
scheduler.add_job(func=check_booking_expiry, trigger="interval", hours=1, id='check_booking_expiry')
scheduler.start()

scheduler.add_job(
    func=send_shift_reminders,
    trigger="interval",
    minutes=30,
    id='shift_reminders'
)

# Run every 5 minutes
scheduler.add_job(
    func=assign_dirty_rooms,
    trigger="interval",
    minutes=5,
    id='assign_dirty_rooms'
)

# Add to scheduler initialization
scheduler.add_job(
    func=cleanup_pending_payments,
    trigger="interval",
    minutes=10,  # Run every 1minutes
    id='cleanup_pending_payments'
)

scheduler.add_job(
    func=handle_missed_shifts,
    trigger="interval",
    minutes=10,
    id='missed_shifts_handler'
)

scheduler.add_job(
    func=cleanup_expired_bookings,
    trigger="interval",
    minutes=30,
    id='cleanup_expired_bookings'
)

scheduler.add_job(
    func=send_shift_otp_job,
    trigger="interval",
    minutes=10,
    id='shift_otp_job_generator'
)

scheduler.add_job(
    func=check_booking_expiry,
    trigger="interval",
    minutes=5,
    id='booking_expiry_check'
)

scheduler.add_job(
    func=generate_rotational_shifts,
    trigger="cron",
    hour=0,
    id='generate_shifts'
)

# Run auto checkout daily at 12:00 PM
scheduler.add_job(
    func=auto_checkout_overdue_bookings,
    trigger="cron",
    hour=12,
    minute=0,
    timezone=NIGERIA_TZ,
    id='auto_checkout_daily'
)


scheduler.add_job(
    func=send_checkout_reminders,
    trigger="cron",
    hour=11,
    minute=50,
    timezone=NIGERIA_TZ,
    id='checkout_reminders'
)

# Check for missed checkouts every 30 minutes
scheduler.add_job(
    func=check_missed_checkouts,
    trigger="interval",
    minutes=3,
    id='missed_checkouts_checker'
)

# Remove this duplicate job as its function doesn't exist
# scheduler.add_job(
#     func=auto_checkout_and_notifications,
#     trigger="interval",
#     minutes=5,
#     id='auto_checkout'
# )

scheduler.add_job(
    func=generate_daily_reports,
    trigger="cron",
    hour=23,
    minute=30,
    id='daily_reports'
)

# In scheduler setup
scheduler.add_job(
    func=assign_housekeeping_tasks,
    trigger="cron",
    hour=8, minute=30,  # 7:30 AM UTC (8:30 AM Nigeria)
    id='morning_cleaning_assignment'
)

scheduler.add_job(
    func=assign_housekeeping_tasks,
    trigger="cron",
    hour=16, minute=0,  # 3:00 PM UTC (4:00 PM Nigeria)
    id='afternoon_cleaning_assignment'
)

scheduler.add_job(
    func=generate_shift_otps,
    trigger="interval",
    minutes=5,
    id='shift_otp_generator'
)

# Make sure OTP job is running
scheduler.add_job(
    func=generate_shift_otp_job,
    trigger="interval",
    minutes=20,
    id='shift_otp_generators'
)

scheduler.add_job(
    func=check_shift_notifications,
    trigger="interval",
    minutes=5,
    id='shift_notifications'
)

scheduler.add_job(
    func=update_overdue_bookings_and_rooms,
    trigger="interval",
    minutes=5,
    id='update_overdue_bookings'
)

# Remove existing housekeeping jobs
scheduler.remove_job('morning_cleaning_assignment')
scheduler.remove_job('afternoon_cleaning_assignment')

# Add new scheduled jobs
scheduler.add_job(
    func=assign_scheduled_cleaning,
    trigger="cron",
    hour=8, minute=0,  # 8:00 AM
    timezone=NIGERIA_TZ,
    id='morning_cleaning_assignment'
)

scheduler.add_job(
    func=assign_scheduled_cleaning,
    trigger="cron",
    hour=16, minute=0,  # 4:00 PM
    timezone=NIGERIA_TZ,
    id='afternoon_cleaning_assignment'
)


def run_automations(trigger_type, context=None):
    """
    Checks for active automations matching the trigger_type and executes their actions.
    :param trigger_type: str, e.g. 'booking_created'
    :param context: dict, extra data for the action (e.g., booking, user_id, etc.)
    """
    automations = Automation.query.filter_by(trigger_type=trigger_type, is_active=True).all()
    for rule in automations:
        # 1. Send Notification
        if rule.action_type == "send_notification":
            message = rule.action_config.get('message') if rule.action_config else f"Automation: {trigger_type.replace('_', ' ').title()}"
            # You can use context to customize the message
            if context:
                if 'booking' in context:
                    message += f" | Booking ID: {context['booking'].id}"
                if 'payment' in context:
                    message += f" | Payment ID: {context['payment'].id}"
                if 'request' in context:
                    message += f" | Maintenance Request ID: {context['request'].id}"
                if 'room' in context:
                    message += f" | Room: {getattr(context['room'], 'name', context['room'].id)}"
                if 'staff' in context:
                    message += f" | Staff: {getattr(context['staff'], 'first_name', '')} {getattr(context['staff'], 'last_name', '')}"
                if 'feedback' in context:
                    message += f" | Feedback ID: {context['feedback'].id}"
            notif = Notification(
                title=rule.name or "Automation Notification",
                message=message,
                user_id=context.get('user_id') if context else None
            )
            db.session.add(notif)
            db.session.commit()
        # 2. Log Event
        elif rule.action_type == "log_event":
            desc = rule.action_config.get('description') if rule.action_config else f"Event: {trigger_type.replace('_', ' ').title()}"
            if context and 'booking' in context:
                desc += f" | Booking ID: {context['booking'].id}"
            if context and 'payment' in context:
                desc += f" | Payment ID: {context['payment'].id}"
            if context and 'request' in context:
                desc += f" | Maintenance Request ID: {context['request'].id}"
            if context and 'room' in context:
                desc += f" | Room: {getattr(context['room'], 'name', context['room'].id)}"
            if context and 'staff' in context:
                desc += f" | Staff: {getattr(context['staff'], 'first_name', '')} {getattr(context['staff'], 'last_name', '')}"
            if context and 'feedback' in context:
                desc += f" | Feedback ID: {context['feedback'].id}"
            log = ActivityLog(
                title=rule.name or f"Automation Log: {trigger_type}",
                description=desc,
                initiator_id=context.get('user_id') if context else getattr(current_user, 'id', None),
                timestamp=datetime.now(NIGERIA_TZ)
            )
            db.session.add(log)
        
        # 3. Add more actions here as needed
        # elif rule.action_type == "send_email":
        #     # Implement email sending logic
        #     pass






# Global cache for signature rooms
_cached_signature_rooms = None
_cached_signature_rooms_timestamp = None
SIGNATURE_ROOM_CACHE_DURATION = timedelta(minutes=30)
NUMBER_OF_SIGNATURE_ROOMS = 6
# Routes
@app.route('/')
def home():
    days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']

    global _cached_signature_rooms, _cached_signature_rooms_timestamp
    selected_signature_rooms = []
    now_dt = datetime.now(NIGERIA_TZ)
    update_overdue_bookings_and_rooms()
    if _cached_signature_rooms and \
       _cached_signature_rooms_timestamp and \
       (now_dt - _cached_signature_rooms_timestamp < SIGNATURE_ROOM_CACHE_DURATION):
        selected_signature_rooms = _cached_signature_rooms
        app.logger.info("Using cached signature rooms.")
    else:
        app.logger.info("Signature rooms cache expired or not found. Regenerating...")
        # Only fetch active rooms
        all_rooms_for_selection = Room.query.filter_by(is_active=True).options(db.joinedload(Room.images)).all()

        if all_rooms_for_selection:
            if len(all_rooms_for_selection) >= NUMBER_OF_SIGNATURE_ROOMS:
                selected_signature_rooms = random.sample(all_rooms_for_selection, NUMBER_OF_SIGNATURE_ROOMS)
            else:
                selected_signature_rooms = all_rooms_for_selection

            _cached_signature_rooms = selected_signature_rooms
            _cached_signature_rooms_timestamp = now_dt
            app.logger.info(f"Selected {len(selected_signature_rooms)} new signature rooms.")
        else:
            app.logger.warning("No rooms found in the database to select signature rooms.")
            selected_signature_rooms = []

    # Only display active rooms
    all_display_rooms = Room.query.filter_by(is_active=True).options(db.joinedload(Room.images)).all()
    room_images = {}
    for room in all_display_rooms:
        primary_image = next((img for img in room.images if img.is_primary), None)
        if not primary_image and room.images:
            primary_image = room.images[0]
        if primary_image and primary_image.filename:
            img_path = os.path.join(app.config['UPLOAD_FOLDER'], primary_image.filename)
            if os.path.exists(img_path):
                room_images[room.id] = convert_image_to_base64(img_path)
            else:
                app.logger.warning(f"Image file not found: {img_path} for room ID {room.id}")
                room_images[room.id] = None
        else:
            room_images[room.id] = None

    user_notifications = []
    if current_user.is_authenticated:
        user_notifications = Notification.query.filter_by(
            user_id=current_user.id,
            is_read=False
        ).order_by(Notification.created_at.desc()).all()

    gallery_images = GalleryImage.query.order_by(GalleryImage.uploaded_at.desc()).limit(6).all()

    return render_template(
        'index.html',
        days=days,
        rooms=all_display_rooms,
        signature_rooms=selected_signature_rooms,
        room_images=room_images,
        notifications=user_notifications,
        gallery_images=gallery_images
    )
@app.template_filter('time_ago')
def time_ago_filter(dt):
    if dt is None:
        return ""
    # Convert to Nigeria time before calculation
    now_ng = datetime.now(NIGERIA_TZ)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt_ng = dt.astimezone(NIGERIA_TZ)
    return humanize.naturaltime(now_ng - dt_ng)

@app.route('/about')
def about():
    return render_template('about.html')

@app.template_filter('timedelta')
def timedelta_filter(dt, delta_days=0):
    return dt - timedelta(days=delta_days)

@app.route('/contact', methods=['GET', 'POST'])
@csrf.exempt
def contact():
    form = ContactForm()  # Create a ContactForm class using Flask-WTF
    
    if form.validate_on_submit():
        # Process form data
        name = form.name.data
        email = form.email.data
        message = form.message.data
        
        try:
            send_email(to_email="josephchukwubike2@gmail.com",
                      subject="Contact Form Submission",
                      body=f"Name: {name}\nEmail: {email}\nMessage: {message}")
            flash('Your message has been sent. Thank you!', 'success')
            return redirect(url_for('contact'))
        except Exception as e:
            app.logger.error(f"Error sending contact form email: {e}")
            flash('Failed to send your message. Please try again.', 'error')
    
    return render_template('contact.html', form=form, google_maps_api_key=app.config['GOOGLE_MAPS_API_KEY'])
@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

# User Authentication

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        first_name = form.first_name.data
        last_name = form.last_name.data
        phone = form.phone.data
        if not phone:
            flash('Phone number is required', 'error')
            return redirect(url_for('register'))
        email = form.email.data
        password = form.password.data
        
        try:
            # Check for existing users first
            if User.query.filter_by(first_name=first_name).first():
                flash('First Name already exists', 'error')
                return redirect(url_for('register'))

            if User.query.filter_by(last_name=last_name).first():
                flash('Last Name already exists', 'error')
                return redirect(url_for('register'))

            new_user = User(
                first_name=first_name,
                last_name=last_name,
                email=email,
                password=generate_password_hash(password),
                status='active',
                created_at=datetime.now(NIGERIA_TZ),
                email_verified=False
            )
            db.session.add(new_user)
            db.session.flush()
            # Assign user role
            user_role = Role.query.filter_by(name='user').first()
            if user_role:
                new_user.roles.append(user_role)
            db.session.commit()

            # --- AUTOMATION TRIGGER ---
            run_automations('user_registered', context={'user': new_user, 'user_id': new_user.id})

            flash('Registration successful! Please check your email to verify your account', 'success')
            # ... send email ...
            return redirect(url_for('login'))

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"REGISTRATION ERROR: {str(e)}")
            flash(f'Registration failed: {str(e)}', 'error')
            return redirect(url_for('register'))

    # ... handle form errors ...
    return render_template('register.html', form=form)

def check_staff_active():
    staff = Staff.query.filter_by(user_id=current_user.id).first()
    if not staff or not staff.is_active:
        flash('Your staff account is deactivated', 'error')
        return False
    return True

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data.lower().strip()
        password = form.password.data
        user = User.query.filter(func.lower(User.email) == email).first()
        
        if user and check_password_hash(user.password, password):
                if user.has_role('staff'):
                    staff = Staff.query.filter_by(user_id=user.id).first()
                    if staff and not staff.is_active:
                        flash('Your staff account is deactivated', 'error')
                        return redirect(url_for('login'))
                # Check if user is approved (for admins/staff)
                if any(role.name in ['admin', 'super_admin', 'staff'] for role in user.roles) and user.status != 'approved':
                    flash('Your account is pending approval', 'warning')
                    return redirect(url_for('login'))

                login_user(user)
                app.logger.info(f"Successful login: {user.email} with roles: {[r.name for r in user.roles]}")

                # Determine redirect target
                next_page = request.args.get('next')
                if user.has_role('super_admin'):
                    return redirect(url_for('admin_dashboard'))
                elif user.has_role('hr'):
                    return redirect(url_for('hr_dashboard'))
                elif user.has_role('receptionist'):
                    return redirect(url_for('receptionist_dashboard'))
                elif user.has_role('finance_admin'):
                    return redirect(url_for('finance_dashboard'))
                elif user.has_role('api_management'):
                    return redirect(url_for('api_management_dashboard'))
                elif user.has_role('housekeeping_supervisor'):
                    return redirect(url_for('housekeeping_dashboard'))
                elif user.has_role('bar_management'):
                    return redirect(url_for('bar_management_dashboard'))
                
                # Updated staff redirect condition
                staff_profile = Staff.query.filter_by(user_id=user.id).first()
                if staff_profile and staff_profile.position:
                    return redirect(url_for('staff_dashboard'))
                else:
                    return redirect(url_for('home'))

                flash('Logged in successfully!', 'success')
                return redirect(next_page)
        else:
                app.logger.warning(f"Failed login attempt for email: {email}")
                flash('Invalid email or password', 'danger')
    return render_template('login.html', form=form)

# Password Reset Routes
@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('profile'))
        
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = ts.dumps(user.email, salt='password-reset-salt')
            reset_url = url_for('reset_password_token', token=token, _external=True)
            
            try:
                msg = Message('Password Reset Request',
                            recipients=[user.email],
                            body=f'''To reset your password, visit the following link:
{reset_url}

If you did not make this request, simply ignore this email.''')
                mail.send(msg)
            except Exception as e:
                app.logger.error(f"Error sending password reset email: {e}")
                flash('Error sending reset email. Please try again.', 'error')
                return redirect(url_for('reset_password_request'))
            
            flash('Password reset instructions sent to your email', 'info')
        return redirect(url_for('login'))
    
    return render_template('reset_password_request.html', form=form)

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('profile'))
        
    try:
        email = ts.loads(token, salt='password-reset-salt', max_age=3600)  # 1 hour expiration
    except:
        flash('The reset link is invalid or has expired', 'danger')
        return redirect(url_for('reset_password_request'))
    
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=email).first()
        if user:
            user.password = generate_password_hash(form.password.data)
            db.session.commit()
            flash('Your password has been updated!', 'success')
            return redirect(url_for('login'))
        
    return render_template('reset_password.html', form=form)



@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('access_token', None)
    session.pop('refresh_token', None)
    flash('Logged out successfully!', 'success')
    return redirect(url_for('home'))

@app.route('/profile')
@role_required(['user', 'super_admin', 'staff'])
def profile():
    user = User.query.get(current_user.id)
    form = EditProfileForm(original_username=user.username, obj=user)
    return render_template('profile.html', user=user, form=form)


# Add to utility functions
def hr_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        if not any(role.name in ['super_admin', 'hr'] for role in current_user.roles):
            abort(403)
        return f(*args, **kwargs)
    return decorated_function



@app.route('/settings', methods=['GET', 'POST'])
@login_required
def user_settings():
    form = UserSettingsForm()
    
    # Load current settings
    if request.method == 'GET':
        form.dark_mode.data = session.get('dark_mode', False)
        form.font_size.data = session.get('font_size', 'medium')
    
    if form.validate_on_submit():
        # Save settings to session
        session['dark_mode'] = form.dark_mode.data
        session['font_size'] = form.font_size.data
        
        flash('Your settings have been saved!', 'success')
        return redirect(url_for('user_settings'))
    
    return render_template('settings.html', form=form)

@app.route('/profile/edit', methods=['GET', 'POST'])
@role_required(['user', 'super_admin', 'staff'])
def edit_profile():
    user = User.query.get(current_user.id)
    form = EditProfileForm(original_username=user.username, obj=user)
    
    if form.validate_on_submit():
        try:
            # Check if username is being changed
            if user.username != form.username.data:
                if User.query.filter_by(username=form.username.data).first():
                    flash('Username already taken!', 'error')
                    return redirect(url_for('edit_profile'))

            user.username = form.username.data
            user.email = form.email.data
            
            if form.password.data:
                user.password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
            
            db.session.commit()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('profile'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Profile update error: {e}")
            flash('Error updating profile', 'error')
    
    return render_template('edit_profile.html', user=user, form=form)


@app.template_filter('format_currency')
def format_currency(value):
    try:
        # Format as Nigerian Naira (₦) with 2 decimal places
        return "₦{:,.2f}".format(float(value))
    except (ValueError, TypeError):
        return "₦0.00"

    
# Or for more advanced currency formatting:
def format_currency(value, currency="₦"):
    try:
        return f"{currency}{float(value):,.2f}"
    except (ValueError, TypeError):
        return "N/A"

app.jinja_env.filters['format_currency'] = format_currency

@app.route('/test-email')
def test_email():
    if send_email("test@example.com", "Test", "Hello"):
        return "Email sent!"
    return "Email failed"

@app.route('/generate-key', methods=['POST'])
@role_required('api_management')
def generate_key():
    # Generate secure key
    key = secrets.token_urlsafe(32)
    # Store hashed key in database
    hashed_key = generate_password_hash(key)
    new_key = APIKey(value=hashed_key, owner_id=current_user.id)
    db.session.add(new_key)
    db.session.commit()
    # Show actual key only once
    flash(f'New API key generated: {key}', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/refresh', methods=['POST'])
def refresh_token():
    refresh_token = request.json.get('refresh_token')
    if not refresh_token:
        return jsonify({'message': 'Refresh token is required'}), 400

    payload = verify_jwt_token(refresh_token)
    if payload == 'Token expired' or payload == 'Invalid token':
        return jsonify({'message': 'Invalid or expired refresh token'}), 401

    user_id = payload.get('sub')
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404

    access_token = create_jwt_token(user.id, user.role, 'access')
    return jsonify({'access_token': access_token}), 200

# Booking Management
@app.route('/rooms')
def rooms():
    rooms = Room.query.filter_by(is_active=True).options(db.joinedload(Room.images)).all()
    room_images = {}
    for room in rooms:
        primary_image = next((img for img in room.images if img.is_primary), None)
        if not primary_image and room.images:
            primary_image = room.images[0]
        if primary_image:
            img_path = os.path.join(app.config['UPLOAD_FOLDER'], primary_image.filename)
            room_images[room.id] = convert_image_to_base64(img_path)
        else:
            room_images[room.id] = None
    return render_template('rooms.html', rooms=rooms, room_images=room_images)



@app.route('/room/<int:room_id>')
def room_detail(room_id):
    room = Room.query.get_or_404(room_id)
    # Fetch ALL images for this room
    room_images = RoomImage.query.filter_by(room_id=room_id).all()
    form = BookingForm()
    # Find primary image or use first image
    primary_image = None
    for img in room_images:
        if img.is_primary:
            primary_image = img
            break
    if not primary_image and room_images:
        primary_image = room_images[0]
    
    # Convert images to base64
    image_data = []
    for img in room_images:
        img_path = os.path.join(app.config['UPLOAD_FOLDER'], img.filename)
        if os.path.exists(img_path):
            image_data.append({
                'id': img.id,
                'data': convert_image_to_base64(img_path),
                'is_primary': img.is_primary
            })
    
    today = datetime.now(NIGERIA_TZ).strftime('%Y-%m-%d')
    return render_template('room_detail.html', 
        room=room, 
        primary_image=image_data[0]['data'] if image_data else None,
        all_images=image_data,
        today=today,  form=form 
    )


@app.route('/booking/confirmation/<int:booking_id>')
@login_required
def booking_confirmation(booking_id):
    booking = Booking.query.get_or_404(booking_id)
    
    # Verify booking ownership
    if booking.user_id != current_user.id:
        abort(403)
    
    return render_template('booking_confirmation.html', 
                         booking=booking,
                         room=booking.room)
# app.py

def room_is_available(room_id, check_in_date, check_out_date):
    # Convert dates to datetime with fixed times
    check_in_dt = datetime.combine(check_in_date, dt_time(14, 0))
    check_out_dt = datetime.combine(check_out_date, dt_time(12, 0))
    
    # Check only against CONFIRMED (paid) bookings
    overlapping = Booking.query.filter(
        Booking.room_id == room_id,
        Booking.check_out_date > check_in_dt,
        Booking.check_in_date < check_out_dt,
        Booking.payment_status == 'paid',  # Only consider paid bookings
        Booking.checked_out == False
    ).count()
    
    return overlapping == 0


def check_booking_expiry():
    with app.app_context():
        expired_bookings = Booking.query.filter(
            and_(
                Booking.otp_expiry < datetime.now(NIGERIA_TZ),
                Booking.check_in_status == 'Pending'
            )
        ).all()
        
        for booking in expired_bookings:
            booking.check_in_status = 'Expired'
            booking.room.status = 'Available'
            db.session.commit()
NIGERIA_TZ = pytz.timezone('Africa/Lagos')



@app.route('/book_room/<int:room_id>', methods=['GET', 'POST'])
@role_required(['user', 'super_admin', 'staff'])
def book_room(room_id):
    # Update booking statuses before processing new booking
    update_overdue_bookings_and_rooms()
    
    room = Room.query.get_or_404(room_id)
    form = BookingForm()
    
    if form.validate_on_submit():
        try:
            # Calculate dates and duration
            nights = (form.check_out_date.data - form.check_in_date.data).days
            if nights <= 0:
                flash('Check-out date must be after check-in date', 'error')
                return render_template('book_room.html', room=room, form=form)
            
            total_price = room.price * nights

            # Create datetime objects with Nigeria timezone
            nigeria_tz = pytz.timezone('Africa/Lagos')
            
            # Combine dates with time (2 PM check-in, 12 PM check-out)
            check_in_dt = nigeria_tz.localize(
                datetime.combine(form.check_in_date.data, dt_time(14, 0))
            )
            check_out_dt = nigeria_tz.localize(
                datetime.combine(form.check_out_date.data, CHECKOUT_TIME)
            )
            
            # Check availability
            overlapping_bookings = Booking.query.filter(
                Booking.room_id == room_id,
                Booking.check_out_date > check_in_dt,
                Booking.check_in_date < check_out_dt,
                Booking.payment_status == 'paid'
            ).count()

            if overlapping_bookings > 0:
                flash('Room is not available for the selected dates', 'error')
                return redirect(url_for('book_room', room_id=room_id))
            
            # Generate payment reference
            unique_reference = f"BOOKING_{datetime.now().strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex}"
            
            # Create booking with full datetime objects
            booking = Booking(
                user_id=current_user.id,
                room_id=room_id,
                check_in_date=check_in_dt,
                check_out_date=check_out_dt,
                total_amount=total_price,
                payment_status='pending',
                payment_reference=unique_reference,
                otp=generate_otp(),
                otp_expiry=datetime.now(NIGERIA_TZ) + timedelta(hours=24)
            )
            db.session.add(booking)
            
            # Update room status
       
            
            # Initialize payment
            payment_data = initialize_paystack_payment(
                email=current_user.email,
                amount=total_price,
                reference=unique_reference,
                metadata={
                    'room_id': room_id,
                    'user_id': current_user.id,
                    'check_in': check_in_dt.isoformat(),
                    'check_out': check_out_dt.isoformat()
                }
            )
            
            if not payment_data or not payment_data.get('status'):
                flash('Payment initialization failed. Please try again.', 'error')
                return redirect(url_for('book_room', room_id=room_id))
            else:
                room.status = 'booked'
                db.session.commit()
            
            return redirect(payment_data['data']['authorization_url'])
            
        except Exception as e:
            app.logger.error(f"Booking error: {str(e)}")
            flash(f'An error occurred: {str(e)}', 'error')
            return redirect(url_for('book_room', room_id=room_id))
    
    return render_template('book_room.html', room=room, form=form)




@app.template_filter('humanize_duration')
def humanize_duration_filter(delta):
    if not delta:
        return ""
    
    total_seconds = int(delta.total_seconds())
    hours, remainder = divmod(total_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    
    if hours > 0:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"



# Add this function to your utility functions section
def update_overdue_bookings_and_rooms():
    with app.app_context():
        try:
            now = datetime.now(NIGERIA_TZ)
            
            # 1. Update overdue bookings that should be checked out
            overdue_bookings = Booking.query.filter(
                Booking.check_out_date < now,
                Booking.checked_out == False
            ).all()
            
            for booking in overdue_bookings:
                booking.check_in_status = 'Checked-out'
                booking.checked_out = True
                booking.checked_out_at = now
                
                # Update room status
                room = Room.query.get(booking.room_id)
                if room:
                    room.status = 'available'
                    room.cleaning_status = 'dirty'
                    room.last_occupied = now.date()
            
            # 2. Release rooms from pending bookings that expired
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
            app.logger.info(f"Updated {len(overdue_bookings)} overdue bookings and {len(expired_bookings)} expired bookings")
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error updating overdue bookings: {str(e)}")

# app.py
@app.route('/request_late_checkout/<int:booking_id>', methods=['POST'])
@login_required
def request_late_checkout(booking_id):
    booking = Booking.query.get_or_404(booking_id)
    
    if request.method == 'POST':
        # Calculate late checkout fee (50% of room rate)
        late_fee = booking.room.price / 2
        booking.late_checkout = True
        booking.late_checkout_fee = late_fee
        booking.total_amount += late_fee
        
        # Extend checkout time to 6 PM
        booking.check_out_date = booking.check_out_date.replace(hour=18, minute=0)
        
        db.session.commit()
        flash(f'Late checkout approved! Fee: ₦{late_fee:.2f}', 'success')
        return redirect(url_for('booking_details', booking_id=booking.id))


@app.route('/edit_booking/<int:booking_id>', methods=['GET', 'POST'])
@login_required
def edit_booking(booking_id):
    booking = Booking.query.get_or_404(booking_id)
    # Only allow editing if payment or booking is pending
    if not (booking.payment_status.lower() == 'pending' or booking.check_in_status.lower() == 'pending'):
        flash('You can only edit bookings that are pending payment or check-in.', 'warning')
        return redirect(url_for('booking_details', booking_id=booking.id))
    # Only the booking owner or admin/staff can edit
    if booking.user_id != current_user.id and current_user.role not in ['admin', 'staff']:
        abort(403)
    form = BookingForm(obj=booking)
    if form.validate_on_submit():
        # Prevent double-booking logic here if you want
        booking.check_in_date = form.check_in_date.data
        booking.check_out_date = form.check_out_date.data
        booking.total_amount = booking.room.price * (form.check_out_date.data - form.check_in_date.data).days
        db.session.commit()
        flash('Booking updated successfully.', 'success')
        return redirect(url_for('booking_details', booking_id=booking.id))
    return render_template('edit_booking.html', form=form, booking=booking)


@app.route('/paystack/booking_callback')
def paystack_booking_callback():
    reference = request.args.get('reference')
    if not reference:
        app.logger.error("No reference provided in callback")
        return redirect(url_for('booking_failed'))

    verification_data = verify_payment(reference)
    if not verification_data or verification_data.get('data', {}).get('status') != 'success':
        app.logger.error("Paystack verification failed or payment not successful")
        return redirect(url_for('booking_failed'))

    try:
        booking = Booking.query.filter_by(payment_reference=reference).first()
        if not booking:
            app.logger.error(f"No booking found for reference: {reference}")
            return redirect(url_for('booking_failed'))

        booking.payment_status = 'paid'
        amount = verification_data['data']['amount'] / 100
        payment = Payment(
            booking_id=booking.id,
            amount=amount,
            payment_method='Paystack',
            reference=reference,
            status='success',
            payment_date=datetime.now(NIGERIA_TZ)
        )
        db.session.add(payment)
        db.session.commit()

        send_booking_confirmation_email(booking)
        notification = Notification(
            user_id=booking.user_id,
            title="Booking Confirmed",
            message=f"Your booking #{booking.id} has been confirmed! Room: {booking.room.name}",
            category="booking"
        )
        db.session.add(notification)
        db.session.commit()

        return redirect(url_for('booking_confirmation', booking_id=booking.id))

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Payment processing error: {str(e)}")
        return redirect(url_for('booking_failed'))





def send_booking_confirmation_email(booking):
    subject = "Booking Confirmation - Hotel Marlin"
    body = render_template('emails/booking_confirmation.txt', booking=booking)
    html = render_template('emails/booking_confirmation.html', booking=booking)
    checkout_otp = booking.generate_checkout_otp()
    
    subject = "Booking Confirmation - Hotel Marlin"
    body = render_template('emails/booking_confirmation.txt', 
                          booking=booking,
                          checkout_otp=checkout_otp)
    msg = Message(
        subject=subject,
        recipients=[booking.user.email],
        body=body,
        html=html,
        sender=app.config['MAIL_DEFAULT_SENDER']
    )
    
    try:
        mail.send(msg)
        app.logger.info(f"Booking confirmation email sent to {booking.user.email}")
    except Exception as e:
        app.logger.error(f"Error sending booking confirmation email: {e}")

def handle_order_payment(verification_data, reference):
    try:
        # Get order from reference
        order = BarOrder.query.filter_by(payment_reference=reference).first()
        if not order:
            app.logger.error(f"Order not found for reference: {reference}")
            return False

        # Verify payment status
        if verification_data['data']['status'] != 'success':
            app.logger.error(f"Payment failed for order {order.id}")
            return False

        # Update order status
        order.payment_status = 'paid'
        order.status = 'completed'
        order.paid_at = datetime.now(NIGERIA_TZ)

        # Update inventory and create sales records
        for item in order.order_items:
            bar_item = db.session.get(BarItem, item.item_id)  # Use db.session.get
            if bar_item:
                bar_item.quantity -= item.quantity
                # Create BarSale record (remove order_id)
                sale = BarSale(
    item_id=bar_item.id,
    quantity_sold=item.quantity,
    total_amount=item.price * item.quantity,
    sale_time=datetime.now(NIGERIA_TZ)
)
                db.session.add(sale)

        db.session.commit()
        
        # Send confirmation
        send_email(
            to_email=order.user.email,
            subject="Order Confirmation",
            body=f"Your order #{order.id} has been confirmed! Total: ₦{order.total_amount:,.2f}"
        )
        
        return True
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Order processing error: {e}")
        return False



@app.route('/booking_failed')
def booking_failed():
    return render_template('booking_failed.html')

@app.route('/order_failed')
def order_failed():
    return render_template('order_failed.html')


@app.route('/order/confirmation/<int:order_id>')
@login_required
def order_confirmation(order_id):
    order = BarOrder.query.get_or_404(order_id)
    # Check user role
    is_admin = any(role.name in [ 'super_admin', 'bar_manager'] for role in current_user.roles)
    return render_template('order_confirmation.html', order=order, is_admin=is_admin)

@app.route('/my_bookings')
@role_required(['user', 'super_admin', 'staff'])
def my_bookings():
    user_id = current_user.id
    bookings = Booking.query.filter_by(user_id=user_id).order_by(Booking.created_at.desc()).all()
    today = datetime.now(NIGERIA_TZ).date()
    return render_template('my_bookings.html', bookings=bookings, today=today)

@app.route('/booking/<int:booking_id>')
@login_required
def booking_details(booking_id):
    booking = Booking.query.get_or_404(booking_id)
    
    # Authorization check
    if booking.user_id != current_user.id and current_user.role not in ['admin', 'staff']:
        abort(403)
    
    # Calculate cancellation cutoff (2 hours 30 minutes before check-in) with timezone awareness
    check_in_utc = booking.check_in_date.replace(tzinfo=timezone.utc)
    cancellation_cutoff = check_in_utc - timedelta(hours=6, minutes=30)

    # Get current time in UTC
    current_utc = datetime.now(NIGERIA_TZ)
    
    return render_template(
        'booking_details.html',
        booking=booking,
        check_in_utc=check_in_utc,
        current_utc=current_utc,
        cancellation_cutoff=cancellation_cutoff,
        normalized_payment_status=booking.payment_status.lower()
    )

@app.route('/create_test_booking')
def create_test_booking():
    test_user = User(
        username='tester',
        email='test@example.com',
        password=generate_password_hash('test123')
    )
    db.session.add(test_user)
    db.session.flush()
    user_role = Role.query.filter_by(name='user').first()
    if user_role:
        test_user.roles.append(user_role)
    
    # Create a test room
    test_room = Room(
        name='Test Suite',
        price=200.00,
        capacity=2,
        status='available'
    )
    db.session.add(test_room)
    
    # Create a test booking
    test_booking = Booking(
        user=test_user,
        room=test_room,
        check_in_date=datetime(2025, 5, 28),
        check_out_date=datetime(2025, 5, 30),
        total_amount=400.00,
        payment_status='paid',  # Lowercase for testing
        payment_reference='TEST_REF_123'
    )
    db.session.add(test_booking)
    
    db.session.commit()
    return 'Test booking created!'

@app.route('/request_cancellation/<int:booking_id>', methods=['GET', 'POST'])
@csrf.exempt
@role_required(['user'])
def request_cancellation(booking_id):
    booking = Booking.query.get_or_404(booking_id)
    
    # Authorization
    if booking.user_id != current_user.id:
        abort(403)
    
    # Validation checks
    if booking.payment_status != 'paid':
        flash('Only paid bookings can be cancelled', 'error')
        return redirect(url_for('booking_details', booking_id=booking.id))

    if request.method == 'POST':
        # Generate cancellation OTP
        cancellation_otp = generate_otp()
        booking.cancellation_otp = cancellation_otp
        booking.cancellation_otp_expiry = datetime.now(NIGERIA_TZ) + timedelta(hours=24)
        booking.cancellation_status = 'requested'
        booking.cancellation_reason = request.form.get('reason')
        db.session.commit()

        # Send notifications
        send_cancellation_notifications(booking, cancellation_otp)
        
        flash('Cancellation request submitted. Staff will contact you.', 'success')
        return redirect(url_for('booking_details', booking_id=booking.id))

    return render_template('request_cancellation.html', booking=booking)

def send_cancellation_notifications(booking, otp):
    # Send to receptionists
    receptionists = User.query.filter_by(role='receptionist').all()
    for user in receptionists:
        msg = Message(
            subject=f"Cancellation Request #{booking.id}",
            recipients=[user.email],
            body=f"""Cancellation Details:
Booking ID: {booking.id}
Guest: {booking.user.username}
OTP: {otp}
Reason: {booking.cancellation_reason}
"""
        )
        mail.send(msg)
    
    # Send confirmation to guest
    msg = Message(
        subject="Cancellation Request Received",
        recipients=[booking.user.email],
        body=f"""Your cancellation OTP: {otp}
This code will expire in 24 hours."""
    )
    mail.send(msg)

# ... [rest of the app.py remains unchanged] ...



@app.route('/confirm_cancellation', methods=['POST'])
@role_required(['receptionist', 'admin'])
def confirm_cancellation():
    otp = request.form.get('otp')
    booking_id = request.form.get('booking_id')
    booking = Booking.query.filter_by(cancellation_otp=otp, id=booking_id).first()

    expiry = booking.cancellation_otp_expiry if booking else None
    if expiry and expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)

    if not booking or not expiry or expiry < datetime.now(NIGERIA_TZ):
        flash('Invalid or expired OTP', 'error')
        return redirect(url_for('receptionist_dashboard'))

    # Refund 70% if Paystack
    refund_success = True
    if hasattr(booking, 'payment_method') and booking.payment_method == 'Paystack':
        refund_success = process_refund(booking, percent=0.7)
        if not refund_success:
            flash('Refund failed', 'error')
            return redirect(url_for('receptionist_dashboard'))

    booking.cancellation_status = 'approved'
    booking.room.status = 'Available'
    booking.payment_status = 'Refunded'
    db.session.commit()

    send_email(
        to_email=booking.user.email,
        subject="Cancellation Approved",
        body="Your booking has been cancelled and 70% refund processed."
    )

    flash('Cancellation confirmed and 70% refund processed', 'success')
    return redirect(url_for('receptionist_dashboard'))

@app.route('/cancel_booking/<int:booking_id>', methods=['POST'])
@role_required(['user', 'super_admin', 'staff'])
def cancel_booking(booking_id):
    booking = Booking.query.get_or_404(booking_id)
    if booking.user_id != current_user.id:
        flash('You do not have permission to cancel this booking.', 'error')
        return redirect(url_for('my_bookings'))
    try:
        db.session.delete(booking)
        db.session.commit()
        flash('Booking cancelled successfully!', 'success')
        return redirect(url_for('my_bookings'))
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error cancelling booking: {e}")
        flash('An error occurred while cancelling your booking. Please try again.', 'error')
        
        return redirect(url_for('my_bookings'))
@app.route('/check-availability', methods=['GET'])
def check_availability():
    try:
        check_in = datetime.strptime(request.args.get('check_in'), '%Y-%m-%d').date()
        check_out = datetime.strptime(request.args.get('check_out'), '%Y-%m-%d').date()
        guests = int(request.args.get('guests', 1))

        # Calculate days
        days = (check_out - check_in).days
        if days <= 0:
            days = 1

        # Find available rooms
        available_rooms = []
        all_rooms = Room.query.all()
        for room in all_rooms:
            if room.capacity >= guests and room_is_available(room.id, check_in, check_out):
                available_rooms.append(room)

        # You must define room_images here as well!
        room_images = {}
        for room in available_rooms:
            room_image = RoomImage.query.filter_by(room_id=room.id, is_primary=True).first()
            if not room_image:
                room_image = RoomImage.query.filter_by(room_id=room.id).first()
            if room_image:
                room_images[room.id] = convert_image_to_base64(os.path.join(app.config['UPLOAD_FOLDER'], room_image.filename))
            else:
                room_images[room.id] = None

        return render_template(
            'availability.html',
            check_in=check_in,
            check_out=check_out,
            guests=guests,
            days=days,  # <-- Pass days to the template
            rooms=available_rooms,
            room_images=room_images
        )

    except ValueError as e:
        app.logger.error(f"Invalid date format: {e}")
        flash('Invalid date format. Please use the date picker.', 'error')
        return redirect(url_for('home'))
    

# Shift Management Routes
@app.route('/shifts')
@role_required(['super_admin', 'hr'])
def shift_list():
    shifts = Shift.query.all()
    return render_template('shift_list.html', shifts=shifts)

@app.route('/admin/shifts')
@admin_required
def manage_shifts():
    page = request.args.get('page', 1, type=int)
    position_filter = request.args.get('position', '')
    date_filter = request.args.get('date', '')

    query = Shift.query.join(Staff)
    
    if position_filter:
        query = query.filter(Staff.position == position_filter)
    
    if date_filter:
        try:
            filter_date = datetime.strptime(date_filter, '%Y-%m-%d').date()
            query = query.filter(Shift.shift_date == filter_date)
        except ValueError:
            pass

    shifts = query.order_by(Shift.shift_date.desc()).paginate(page=page, per_page=20)
    
    positions = db.session.query(Staff.position).distinct().all()
    positions = [p[0] for p in positions if p[0]]
    
    return render_template('admin_shifts.html', 
                         shifts=shifts,
                         positions=positions)


# Shift Schedule View
@app.route('/shifts/schedule')
@role_required(['super_admin', 'hr'])
def shift_schedule():
    # Get all distinct positions from shifts
    positions = db.session.query(Shift.position).distinct().all()
    positions = [p[0] for p in positions if p[0]]  # Filter out empty positions
    
    # Get all shifts with their staff information
    shifts = Shift.query.options(db.joinedload(Shift.staff)).all()
    
    # Group shifts by date
    dates = sorted({shift.shift_date for shift in shifts}, reverse=False)
    
    return render_template('shift_schedule.html',
                         shifts=shifts,
                         positions=positions,
                         dates=dates)


# Shift Rotation Logic
def create_shift_rotation(positions):
    # Implement your rotation logic here
    # Example: 3 shifts per day, rotating weekly
    pass

@app.route('/staff/shifts')
@login_required
@role_required(['staff', 'super_admin', 'hr', 'bar_manager', 'receptionist'])
def staff_shifts():
    # Get staff profile for current user
    staff = Staff.query.filter_by(user_id=current_user.id).first()
    if not staff:
        flash('Staff profile not found', 'error')
        return redirect(url_for('staff_dashboard'))
    
    # Get current UTC time
    current_utc = datetime.now(NIGERIA_TZ)
    
    # Get shifts for the next 7 days
    start_date = current_utc.date()
    end_date = start_date + timedelta(days=7)
    
    shifts = Shift.query.filter(
        Shift.staff_id == staff.id,
        Shift.shift_date >= start_date,
        Shift.shift_date <= end_date
    ).order_by(Shift.shift_date.asc(), Shift.start_time.asc()).all()
    
    # Process shifts - convert to UTC and determine status
    for shift in shifts:
        # Convert start_time to UTC if naive
        if shift.start_time.tzinfo is None:
            shift.start_time_utc = shift.start_time.replace(tzinfo=timezone.utc)
        else:
            shift.start_time_utc = shift.start_time.astimezone(timezone.utc)
            
        # Convert end_time to UTC if naive
        if shift.end_time.tzinfo is None:
            shift.end_time_utc = shift.end_time.replace(tzinfo=timezone.utc)
        else:
            shift.end_time_utc = shift.end_time.astimezone(timezone.utc)
            
        # Calculate status
        if shift.start_time_utc <= current_utc <= shift.end_time_utc:
            shift.status = "Active"
        elif shift.start_time_utc > current_utc:
            shift.status = "Upcoming"
        else:
            shift.status = "Completed"
    
    return render_template(
        'staff_shifts.html',
        shifts=shifts,
        staff=staff,
        current_utc=current_utc,
        current_local=datetime.now().astimezone()  # Local time for display
    )
#

# Add this to utility functions
def get_staff_from_user(user_id):
    return Staff.query.filter_by(user_id=user_id).first()

# Updated Attendance Verification Route
@app.route('/attendance/verify', methods=['POST'])
@role_required(['hr', 'super_admin'])
def verify_attendance():
    otp = request.form.get('otp')
    staff_id = request.form.get('staff_id')
    
    staff = Staff.query.get(staff_id)
    if not staff:
        flash('Staff not found', 'error')
        return redirect(url_for('hr_dashboard'))
    
    now = datetime.now(NIGERIA_TZ)
    
    # Find active shift with matching OTP
    shift = Shift.query.filter(
        Shift.staff_id == staff.id,
        Shift.attendance_otp == otp,
        Shift.otp_expiry >= now
    ).first()

    if shift:
        # Check if attendance already exists
        existing_attendance = Attendance.query.filter(
            Attendance.staff_id == staff.id,
            Attendance.shift_id == shift.id
        ).first()
        
        if existing_attendance:
            flash('Attendance already recorded', 'warning')
            return redirect(url_for('hr_dashboard'))
        
        # Create attendance record
        attendance = Attendance(
            staff_id=staff.id,
            shift_id=shift.id,
            clock_in_time=now,
            date=now.date(),
            status='on-time' if now <= shift.start_time else 'late'
        )
        db.session.add(attendance)
        
        # Update shift status
        shift.attendance_status = attendance.status
        db.session.commit()
        
        flash(f'Check-in recorded for {staff.first_name}', 'success')
    else:
        flash('Invalid OTP or expired', 'error')
    
    return redirect(url_for('hr_dashboard'))

#

@app.route('/staff/tasks')
@role_required(['staff'])
def staff_tasks():
    staff = Staff.query.filter_by(user_id=current_user.id).first()
    maintenance_tasks = MaintenanceRequest.query.filter_by(staff_id=staff.id).all()
    cleaning_assignments = CleaningLog.query.filter_by(cleaned_by_id=staff.id).all()
    return render_template('staff_tasks.html', 
                         maintenance_tasks=maintenance_tasks,
                         cleaning_assignments=cleaning_assignments)

@app.route('/staff/profile')
@role_required(['staff', 'hr', 'super_admin'])
def staff_profile():
    staff = Staff.query.filter_by(user_id=current_user.id).first()
    return render_template('staff_profile.html', staff=staff)

@app.route('/shifts/add', methods=['GET', 'POST'])
@role_required(['super_admin', 'hr'])
def add_shift():
    if request.method == 'POST':
        staff_id = request.form.get('staff_id')
        shift_start = request.form.get('shift_start')
        shift_end = request.form.get('shift_end')
        
        try:
            staff = Staff.query.get_or_404(staff_id)
            start_otp = generate_otp()
            shift = Shift(
                staff_id=staff.id,
                shift_start=datetime.strptime(shift_start, '%Y-%m-%dT%H:%M'),
                shift_end=datetime.strptime(shift_end, '%Y-%m-%dT%H:%M') if shift_end else None,
                start_otp=start_otp,
                date=datetime.strptime(shift_start, '%Y-%m-%dT%H:%M').date()
            )
            db.session.add(shift)
            db.session.commit()
            
            send_shift_otp(staff, "checkin", start_otp, shift.shift_start)
            
            flash('Shift added successfully', 'success')
            return redirect(url_for('shift_list'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error adding shift: {e}")
            flash('Error adding shift', 'error')
    return render_template('add_shift.html', staff_members=Staff.query.all())


@app.route('/shifts/end/<int:shift_id>', methods=['POST'])
@role_required(['super_admin', 'hr'])
def end_shift(shift_id):
    shift = Shift.query.get_or_404(shift_id)
    try:
        end_otp = generate_otp()
        shift.end_otp = end_otp
        shift.shift_end = datetime.now(NIGERIA_TZ)
        db.session.commit()
        
        send_shift_otp(shift.staff, "checkout", end_otp, shift.shift_end)
        flash('Shift ended successfully', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error ending shift: {e}")
        flash('Error ending shift', 'error')
    return redirect(url_for('shift_list'))

# Updated Attendance with OTP Verification
@app.route('/attendance/clock_in', methods=['POST'])
@role_required(['staff'])
def clock_in():
    staff_user_id = session.get('user_id')
    staff = Staff.query.filter_by(user_id=staff_user_id).first()
    otp = request.form.get('otp')
    
    current_shift = Shift.query.filter(
        Shift.staff_id == staff.id,
        Shift.shift_start <= datetime.now(NIGERIA_TZ),
        Shift.shift_end >= datetime.now(NIGERIA_TZ)
    ).first()

    if not current_shift or current_shift.start_otp != otp:
        flash('Invalid OTP or no active shift', 'error')
        return redirect(url_for('dashboard'))

    attendance = Attendance(
        staff_id=staff.id,
        clock_in_time=datetime.now(NIGERIA_TZ),
        shift_id=current_shift.id
    )
    db.session.add(attendance)
    db.session.commit()
    flash('Clocked in successfully', 'success')
    return redirect(url_for('dashboard'))

@app.route('/attendance/clock_out', methods=['POST'])
@role_required(['staff'])
def clock_out():
    staff_user_id = session.get('user_id')
    staff = Staff.query.filter_by(user_id=staff_user_id).first()
    otp = request.form.get('otp')
    
    current_shift = Shift.query.filter(
        Shift.staff_id == staff.id,
        Shift.shift_end >= datetime.now(NIGERIA_TZ)
    ).first()

    if not current_shift or current_shift.end_otp != otp:
        flash('Invalid OTP or no active shift', 'error')
        return redirect(url_for('dashboard'))

    attendance = Attendance.query.filter_by(
        staff_id=staff.id,
        clock_out_time=None
    ).first()
    
    if attendance:
        attendance.clock_out_time = datetime.now(NIGERIA_TZ)
        db.session.commit()
        flash('Clocked out successfully', 'success')
    return redirect(url_for('dashboard'))

 
#staff register
@app.route('/staff/register', methods=['GET', 'POST'])
@role_required(['super_admin'])
def staff_register():
    form = StaffRegistrationForm()
    if form.validate_on_submit():
        if not form.position.data:
            flash('Position is required', 'error')
            return render_template('staff_register.html', form=form)
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already registered!', 'error')
        try:
            image = form.profile_image.data
            filename = None
            if image and allowed_file(image.filename):
                filename = secure_filename(f"{uuid.uuid4().hex}_{image.filename}")
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                image.save(image_path)
            else:
                filename = None

            hashed_password = generate_password_hash(form.password.data)
            new_user = User(
                username=form.email.data,
                password=hashed_password,
                email=form.email.data
            )
            db.session.add(new_user)
            db.session.flush()
            # Assign staff role
            staff_role = Role.query.filter_by(name='staff').first()
            if staff_role:
                new_user.roles.append(staff_role)

            new_staff = Staff(
                user_id=new_user.id,  # Now valid due to the model update
          
                first_name=form.first_name.data,
                last_name=form.last_name.data,
                position=form.position.data,  # This is for position
                role=form.role.data,
                is_active=True,
                email=form.email.data,
                password=hashed_password,
                phone_number=form.phone_number.data,
                profile_image=filename
            )
            db.session.add(new_staff)
            db.session.commit()
            run_automations('staff_registered', context={'staff': new_staff, 'user_id': new_user.id})
            flash('Staff registered successfully', 'success')
            return redirect(url_for('staff_list'))

            # Assign to housekeeping shift rotation
            if form.position.data == 'Housekeeper':
                assign_housekeeping_shifts(new_staff)
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Staff registration error: {e}")
            flash('Error registering staff', 'error')
    return render_template('staff_register.html', form=form)


# Updated staff dashboard
# routes.py - Enhanced Staff Dashboard
@app.route('/staff/dashboard')
@role_required(['staff'])
def staff_dashboard():
    # Get staff profile for current user
    staff = Staff.query.filter_by(user_id=current_user.id).first_or_404()
    now = datetime.now(NIGERIA_TZ)
    
    # 1. Get current shift
    current_shift = Shift.query.filter(
        Shift.staff_id == staff.id,
        Shift.start_time <= now,
        Shift.end_time >= now
    ).first()
    
    # 2. Get upcoming shifts (next 3 days)
    upcoming_shifts = Shift.query.filter(
        Shift.staff_id == staff.id,
        Shift.start_time > now,
        Shift.start_time <= now + timedelta(days=3)
    ).order_by(Shift.start_time.asc()).all()
    
    # 3. Get recent attendance (last 7 days)
    recent_attendance = Attendance.query.filter(
        Attendance.staff_id == staff.id,
        Attendance.date >= now.date() - timedelta(days=7)
    ).order_by(Attendance.clock_in_time.desc()).limit(5).all()
    
    # 4. Get maintenance tasks
    maintenance_tasks = MaintenanceRequest.query.filter(
        MaintenanceRequest.staff_id == staff.id,
        MaintenanceRequest.status.in_(['Open', 'In Progress'])
    ).order_by(MaintenanceRequest.request_time.desc()).all()
    
    # 5. Get cleaning assignments
    cleaning_assignments = CleaningAssignment.query.filter_by(
        staff_id=staff.id
    ).order_by(
        CleaningAssignment.priority.asc(),
        CleaningAssignment.due_by.asc()
    ).all()
    
    # Group cleaning assignments
    pending_assignments = [a for a in cleaning_assignments if a.status == 'pending']
    in_progress_assignments = [a for a in cleaning_assignments if a.status == 'in_progress']
    completed_assignments = [a for a in cleaning_assignments if a.status == 'completed']
    
    # Count completed tasks today
    completed_today = CleaningLog.query.filter(
        CleaningLog.staff_id == staff.id,
        CleaningLog.status == 'completed',
        CleaningLog.end_time >= now - timedelta(hours=24)
    ).count()
      # Get current shift with OTP
    now = datetime.now(NIGERIA_TZ)
    current_shifts = Shift.query.filter(
        Shift.staff_id == staff.id,
        Shift.start_time <= now,
        Shift.otp_expiry >= now,
        Shift.attendance_otp.isnot(None)
    ).first()
    return render_template('staff_dashboard.html',
        staff=staff,
        current_shift=current_shift,
        upcoming_shifts=upcoming_shifts,
        recent_attendance=recent_attendance,
        maintenance_tasks=maintenance_tasks,
        pending_assignments=pending_assignments,
        in_progress_assignments=in_progress_assignments,
        completed_assignments=completed_assignments,
        completed_today=completed_today, show_id_card=True, # Add this line
        current_shifts=current_shifts
    )
# utils.py - Smart Assignment System
def assign_housekeeping_tasks():
    with app.app_context():
        try:
            # Get current shift and housekeeping staff
            now = datetime.now(NIGERIA_TZ)
            current_shifts = Shift.query.filter(
                Shift.start_time <= now,
                Shift.end_time >= now,
                Shift.position == 'Housekeeper'
            ).all()
            
            if not current_shifts:
                return
                
            # Get available staff with current workload
            staff_workload = {}
            for shift in current_shifts:
                staff = Staff.query.get(shift.staff_id)
                if staff and staff.is_active:
                    # Count in-progress tasks
                    current_tasks = CleaningAssignment.query.filter(
                        CleaningAssignment.staff_id == staff.id,
                        CleaningAssignment.status == 'in_progress'
                    ).count()
                    staff_workload[staff.id] = {
                        'staff': staff,
                        'current_tasks': current_tasks,
                        'total_minutes': 0
                    }
            
            # Get rooms needing cleaning with priorities
            rooms_to_clean = get_rooms_needing_cleaning()
            
            # Assign tasks intelligently
            for room in rooms_to_clean:
                # Find best staff (least busy with capacity)
                best_staff = None
                min_workload = float('inf')
                
                for staff_id, workload in staff_workload.items():
                    # Skip if staff already at max capacity (2 concurrent tasks)
                    if workload['current_tasks'] >= 2:
                        continue
                    
                    # Calculate current workload score
                    workload_score = workload['current_tasks'] * 60 + workload['total_minutes']
                    
                    if workload_score < min_workload:
                        min_workload = workload_score
                        best_staff = staff_id
                
                if best_staff:
                    # Create assignment
                    assignment = CleaningAssignment(
                        room_id=room.id,
                        staff_id=best_staff,
                        due_by=now + timedelta(minutes=room.estimated_cleaning_time),
                        priority=room.priority,
                        estimated_duration=room.estimated_cleaning_time
                    )
                    db.session.add(assignment)
                    
                    # Update room status
                    room.cleaning_status = 'assigned'
                    
                    # Update staff workload
                    staff_workload[best_staff]['current_tasks'] += 1
                    staff_workload[best_staff]['total_minutes'] += room.estimated_cleaning_time
            
            db.session.commit()
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Task assignment error: {str(e)}")


def get_rooms_needing_cleaning():
    now = datetime.now(NIGERIA_TZ)
    today = now.date()
    
    # High priority: Checked out today
    high_priority = Room.query.filter(
        Room.cleaning_status == 'dirty',
        Room.last_occupied == today
    ).all()
    
    # Medium priority: Checked out yesterday
    medium_priority = Room.query.filter(
        Room.cleaning_status == 'dirty',
        Room.last_occupied == today - timedelta(days=1)
    ).all()
    
    # Low priority: Occupied but needs cleaning
    low_priority = Room.query.filter(
        Room.status == 'occupied',
        Room.last_cleaned < today - timedelta(days=1)
    ).all()
    
    # Assign priorities and estimated times
    for room in high_priority:
        room.priority = 1
        room.estimated_cleaning_time = 45  # minutes
    
    for room in medium_priority:
        room.priority = 2
        room.estimated_cleaning_time = 35
    
    for room in low_priority:
        room.priority = 3
        room.estimated_cleaning_time = 25
    
    return high_priority + medium_priority + low_priority

@app.route('/staff/assignment/update/<int:assignment_id>', methods=['POST'])
@role_required(['staff'])
def update_assignment_status(assignment_id):
    assignment = CleaningAssignment.query.get_or_404(assignment_id)
    if assignment.staff.user_id != current_user.id:
        abort(403)
    
    action = request.form.get('action')
    
    if action == 'start':
        assignment.status = 'in_progress'
        assignment.room.cleaning_status = 'in_progress'
        
        # Create log
        log = CleaningLog(
            assignment_id=assignment.id,
            start_time=datetime.now(NIGERIA_TZ),
            status='in_progress'
        )
        db.session.add(log)
        
    elif action == 'complete':
        assignment.status = 'completed'
        assignment.room.cleaning_status = 'clean'
        assignment.room.last_cleaned = datetime.now(NIGERIA_TZ)
        
        log = CleaningLog.query.filter_by(assignment_id=assignment.id).first()
        if log:
            log.end_time = datetime.now(NIGERIA_TZ)
            log.status = 'completed'
            log.notes = request.form.get('notes', '')
    
    elif action == 'skip':
        assignment.status = 'completed'
        assignment.room.cleaning_status = 'needs_attention'
        
        log = CleaningLog.query.filter_by(assignment_id=assignment.id).first()
        if log:
            log.end_time = datetime.now(NIGERIA_TZ)
            log.status = 'skipped'
            log.notes = request.form.get('notes', 'Skipped by staff')
    
    db.session.commit()
    return redirect(url_for('staff_dashboard'))

@app.route('/staff/attendance')
@role_required(['staff'])
def staff_attendance():
    staff = Staff.query.filter_by(user_id=current_user.id).first()
    if not staff:
        flash('Staff profile not found', 'error')
        return redirect(url_for('staff_dashboard'))
    
    # Get filter parameters
    filter_type = request.args.get('filter', 'all')
    page = request.args.get('page', 1, type=int)
    
    # Base query
    query = Attendance.query.filter_by(staff_id=staff.id)
    
    # Apply filters
    if filter_type == 'week':
        week_ago = datetime.now(NIGERIA_TZ) - timedelta(days=7)
        query = query.filter(Attendance.date >= week_ago.date())
    elif filter_type == 'month':
        month_ago = datetime.now(NIGERIA_TZ) - timedelta(days=30)
        query = query.filter(Attendance.date >= month_ago.date())
    
    # Order and paginate
    attendances = query.order_by(Attendance.date.desc()).paginate(page=page, per_page=15)
    
    return render_template('staff_attendance.html', 
                         attendances=attendances,
                         filter_type=filter_type)




@app.route('/staff/edit/<int:staff_id>', methods=['GET', 'POST'])
@role_required(['super_admin'])
def edit_staff(staff_id):
    staff = Staff.query.get_or_404(staff_id)
    form = StaffEditForm(
        original_staff_id=staff.staff_id,
        original_email=staff.email,
        original_phone=staff.phone_number,
        obj=staff
    )
    
    # Clear file field data to prevent string conflict
    form.profile_image.data = None  # Important fix
    
    if form.validate_on_submit():
        try:
            # Handle image upload only if new file is provided
            if form.profile_image.data and hasattr(form.profile_image.data, 'filename'):
                image = form.profile_image.data
                if image and allowed_file(image.filename):
                    # Remove old image
                    if staff.profile_image:
                        old_path = os.path.join(app.config['UPLOAD_FOLDER'], staff.profile_image)
                        if os.path.exists(old_path):
                            os.remove(old_path)
                    # Save new image
                    filename = secure_filename(f"{uuid.uuid4().hex}_{image.filename}")
                    image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    staff.profile_image = filename

            # Update other fields
            staff.first_name = form.first_name.data
            staff.last_name = form.last_name.data
            staff.email = form.email.data
            staff.phone_number = form.phone_number.data
            staff.role = form.role.data
            staff.position = form.position.data

            db.session.commit()
            flash('Staff member updated successfully', 'success')
            return redirect(url_for('staff_list'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error updating staff: {traceback.format_exc()}")
            flash(f'Error updating staff member: {str(e)}', 'error')
    
    return render_template('edit_staff.html', form=form, staff=staff)



from decimal import Decimal

# Add this to your app.py
@app.template_filter('to_decimal')
def to_decimal_filter(value):
    try:
        return Decimal(str(value))
    except:
        return Decimal('0.0')



@app.route('/staff/delete/<int:staff_id>', methods=['POST'])
@role_required(['super_admin'])
def delete_staff(staff_id):
    staff = Staff.query.get_or_404(staff_id)
    user = User.query.get(staff.user_id)
    
    try:
        # Delete associated user and staff records
        db.session.delete(staff)
        if user:
            db.session.delete(user)
        db.session.commit()
        flash('Staff member deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting staff: {traceback.format_exc()}")
        flash(f'Error deleting staff member: {str(e)}', 'error')
    
    return redirect(url_for('staff_list'))

@app.route('/staff/list')
@role_required(['super_admin',])
def staff_list():
    staff_members = Staff.query.all()
    return render_template('staff_list.html', staff_members=staff_members)

@app.route('/attendance/records')
@role_required(['super_admin', 'staff'])
def attendance_records():
    if session.get('user_role') == 'staff':
        staff_user_id = session.get('user_id')
        staff = Staff.query.filter_by(user_id=staff_user_id).first()
        if not staff:
            flash('Staff not found', 'error')
            return redirect(url_for('home'))
        attendances = Attendance.query.filter_by(staff_id=staff.id).all()
    else:
        attendances = Attendance.query.all()
    return render_template('attendance_records.html', attendances=attendances)

# Bar Management

@app.route('/bar/sales-records')
@role_required(['bar_manager', 'super_admin'])
def bar_sales_records():
    # Get query parameters for filtering
    page = request.args.get('page', 1, type=int)
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    today = datetime.now(NIGERIA_TZ).date()
    
    # Calculate today's revenue
    today_sales = BarSale.query.filter(
        func.date(BarSale.sale_time) == today
    ).all()
    today_revenue = sum(sale.total_amount for sale in today_sales)

    # Get all bar items
    bar_items = BarItem.query.order_by(BarItem.quantity.asc()).all()
    total_products = len(bar_items)
    low_stock_items = [item for item in bar_items if item.quantity < 10]

    # Popular items calculation (last 7 days)
    popular_items = db.session.query(
        BarItem.name,
        func.sum(BarSale.quantity_sold).label('total_sold')
    ).join(BarSale).filter(
        BarSale.sale_time >= datetime.now(NIGERIA_TZ) - timedelta(days=7)
    ).group_by(BarItem.name).order_by(func.sum(BarSale.quantity_sold).desc()).limit(5).all()

    # Convert to JSON-serializable format
    popular_items_serializable = [[item[0], item[1]] for item in popular_items]

    # Sales trends data (last 7 days)
    sales_data = []
    sales_labels = []
    for i in range(6, -1, -1):
        day = today - timedelta(days=i)
        daily_sales = BarSale.query.filter(
            func.date(BarSale.sale_time) == day
        ).count()
        sales_data.append(daily_sales)
        sales_labels.append(day.strftime('%b %d'))

    # Main sales query
    query = BarSale.query.order_by(BarSale.sale_time.desc())
    
    # Date filtering
    if start_date:
        start_date = datetime.strptime(start_date, '%Y-%m-%d')
        query = query.filter(BarSale.sale_time >= start_date)
    if end_date:
        end_date = datetime.strptime(end_date, '%Y-%m-%d')
        query = query.filter(BarSale.sale_time <= end_date)
    
    # Pagination
    sales = query.paginate(page=page, per_page=20, error_out=False)
    
    return render_template('bar_sales_records.html', 
        sales=sales,
        today_revenue=today_revenue,
        total_products=total_products,
        low_stock_items=low_stock_items,
        popular_items=popular_items_serializable,
        sales_data=sales_data,
        sales_labels=sales_labels,
        bar_items=bar_items,
        title='Sales Records'
    )

@app.route('/bar/print-queue')
@login_required
def bar_print_queue():
    # Only allow managers/admins
    if not any(role.name in ['admin', 'super_admin', 'manager'] for role in current_user.roles):
        abort(403)
    orders = BarOrder.query.filter_by(payment_status='paid', is_printed=False).all()
    return render_template('bar_print_queue.html', orders=orders)




@app.route('/bar/dashboard')
@role_required(['bar_manager', 'super_admin'])
def bar_dashboard():
    # Today's sales calculation
    today = datetime.now(NIGERIA_TZ).date()
    today_sales = BarSale.query.filter(
    func.date(BarSale.sale_time) == today).all()
    today_revenue = sum(sale.total_amount for sale in today_sales)

    # Inventory stats
    bar_items = BarItem.query.order_by(BarItem.quantity.asc()).all()
    total_products = len(bar_items)
    low_stock_items = [item for item in bar_items if item.quantity < 10]

    # Popular items calculation (last 7 days)
    popular_items = db.session.query(
        BarItem.name,
        func.sum(BarSale.quantity_sold).label('total_sold')
    ).join(BarSale).filter(
        BarSale.sale_time >= datetime.now(NIGERIA_TZ) - timedelta(days=7)
    ).group_by(BarItem.name).order_by(func.sum(BarSale.quantity_sold).desc()).limit(5).all()

    # Convert Row objects to JSON-serializable format
    popular_items_serializable = [
        [item[0], item[1]] for item in popular_items
    ]

    # Sales trends data (last 7 days)
    sales_data = []
    sales_labels = []
    for i in range(6, -1, -1):
        day = today - timedelta(days=i)
        daily_sales = BarSale.query.filter(
            func.date(BarSale.sale_time) == day
        ).count()
        sales_data.append(daily_sales)
        sales_labels.append(day.strftime('%b %d'))

    return render_template('bar_dashboard.html',
        today_revenue=today_revenue,
        total_products=total_products,
        low_stock_items=low_stock_items,
        popular_items=popular_items_serializable,  # Use the serializable version
        sales_data=sales_data,
        sales_labels=sales_labels,
        bar_items=bar_items
    )



@app.route('/bar/items')
@role_required(['super_admin', 'staff', 'bar_manager'])
def bar_items():
    bar_items = BarItem.query.all()
    return render_template('bar_items.html', bar_items=bar_items)
@app.route('/bar/items/add', methods=['GET', 'POST'])
@role_required(['super_admin', 'bar_manager'])
def add_bar_item():
    form = BarItemForm()
    
    if form.validate_on_submit():
        try:
            # Handle image upload
            filename = None
            if form.image.data:
                image = form.image.data
                if allowed_file(image.filename):
                    filename = secure_filename(f"{uuid.uuid4().hex}_{image.filename}")
                    image.save(os.path.join(app.config['BAR_ITEM_UPLOAD_FOLDER'], filename))

            new_item = BarItem(
                name=form.name.data,
                price=form.price.data,
                quantity=form.quantity.data,
                image=filename  # Save filename to database
            )
            db.session.add(new_item)
            db.session.commit()
            flash('Item added successfully', 'success')
            return redirect(url_for('bar_items'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error adding bar item: {e}")
            flash('An error occurred while adding the item', 'error')
    
    return render_template('add_bar_item.html', form=form)


@app.route('/bar/items/edit/<int:item_id>', methods=['GET', 'POST'])
def edit_bar_item(item_id):
    item = BarItem.query.get_or_404(item_id)
    form = BarItemForm(obj=item)
    
    if form.validate_on_submit():
        # Handle image update
        if form.image.data:
            # Delete old image if exists
            if item.image:
                old_path = os.path.join(app.config['BAR_ITEM_UPLOAD_FOLDER'], item.image)
                if os.path.exists(old_path):
                    os.remove(old_path)
            
            # Save new image
            image = form.image.data
            filename = secure_filename(f"{uuid.uuid4().hex}_{image.filename}")
            image.save(os.path.join(app.config['BAR_ITEM_UPLOAD_FOLDER'], filename))
            item.image = filename
        
        # Update other fields
        item.name = form.name.data
        item.price = form.price.data
        item.quantity = form.quantity.data
        
        db.session.commit()
        flash('Item updated!', 'success')
        return redirect(url_for('bar_items'))
    
    return render_template('edit_bar_item.html', form=form, item=item)

# app.py
@app.route('/bar/items/delete/<int:item_id>', methods=['POST'])
def delete_bar_item(item_id):
    item = BarItem.query.get_or_404(item_id)
    try:
        # Delete associated image
        if item.image:
            image_path = os.path.join(app.config['BAR_ITEM_UPLOAD_FOLDER'], item.image)
            if os.path.exists(image_path):
                os.remove(image_path)
        
        db.session.delete(item)
        db.session.commit()
        flash('Item deleted', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error: {str(e)}', 'error')
    
    return redirect(url_for('bar_items'))

@app.route('/bar/sale', methods=['POST'])
@role_required(['super_admin', 'staff', 'bar_manager'])
def bar_sale():
    if request.method == 'POST':
        try:
            item_id = request.form.get('item_id')
            quantity = int(request.form.get('quantity'))
            staff_id = current_user.id  # Get current staff/user ID
            
            item = BarItem.query.get_or_404(item_id)
            staff = Staff.query.get_or_404(staff_id)

            if quantity > item.quantity:
                flash('Not enough stock', 'error')
                return redirect(url_for('bar_sale'))

            # Create sale record
            sale = BarSale(
                item_id=item.id,
                quantity_sold=quantity,
                total_amount=item.price * quantity,
                staff_id=staff.id,
                sale_time=datetime.now(NIGERIA_TZ)
            )

            # Update inventory
            item.quantity -= quantity
            
            db.session.add(sale)
            db.session.commit()
            
            flash('Sale recorded and inventory updated', 'success')
            return redirect(url_for('bar_sales_records'))

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Bar sale error: {str(e)}")
            flash('Error processing sale', 'error')
            return redirect(url_for('bar_sale'))


@app.route('/bar/sale/callback')
def bar_sale_callback():
    try:
        reference = session.get('payment_reference')
        verification_data = verify_paystack_payment(reference)
        
        if verification_data['data']['status'] == 'success':
            metadata = verification_data['data']['metadata']
            item_id = metadata.get('item_id')
            quantity = int(metadata.get('quantity'))
            
            item = BarItem.query.get(item_id)
            if not item:
                raise ValueError("Item not found")
            
            # Update inventory
            item.quantity -= quantity
            
            # Record sale
            sale = BarSale(
                item_id=item_id,
                quantity_sold=quantity,
                total_amount=verification_data['data']['amount'] / 100,
                payment_method='Paystack',
                sale_time=datetime.now(NIGERIA_TZ)
            )
            
            db.session.add(sale)
            db.session.commit()
            
            flash('Payment verified and inventory updated', 'success')
            return redirect(url_for('bar_sales_records'))
            
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Callback error: {str(e)}")
        flash('Error completing transaction', 'error')
        return redirect(url_for('bar_sale'))


@app.route('/cleaning_logs')
@role_required(['super_admin', 'staff', 'housekeeping_supervisor'])
def cleaning_logs():
    page = request.args.get('page', 1, type=int)
    
    # Query cleaning logs with related room and staff data
    logs = CleaningLog.query.options(
        db.joinedload(CleaningLog.room),
        db.joinedload(CleaningLog.staff)
    ).order_by(CleaningLog.start_time.desc()).paginate(page=page, per_page=10)
    
    return render_template('cleaning_logs.html', logs=logs)

@app.route('/cleaning_logs/add', methods=['GET', 'POST'])
@role_required(['super_admin', 'staff'])
def add_cleaning_log():
    if request.method == 'POST':
        room_id = request.form.get('room_id')
        cleaned_by_id = request.form.get('cleaned_by_id')
        date = request.form.get('date')
        notes = request.form.get('notes')
        room = Room.query.get_or_404(room_id)

        cleaner = Staff.query.get(cleaned_by_id)
        if not cleaner:
            flash('Invalid Staff ID', 'error')
            return render_template('add_cleaning_log.html')

        if not date:
            flash('Date is required', 'error')
            return render_template('add_cleaning_log.html')
        try:
            date = datetime.strptime(date, '%Y-%m-%d').date()
            log = CleaningLog(room_id=room_id, cleaned_by_id=cleaned_by_id, date=date, notes=notes)
            db.session.add(log)
            db.session.commit()
            flash('Cleaning log added successfully', 'success')
            return redirect(url_for('cleaning_logs'))
        except ValueError:
            flash('Invalid date format. Please use YYYY-MM-DD', 'error')
            return render_template('add_cleaning_log.html')
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error adding cleaning log: {e}")
            flash('An error occurred while adding the log', 'error')
            return render_template('add_cleaning_log.html')
    staff_members = Staff.query.all()
    return render_template(
    'add_cleaning_log.html',
    staff_members=staff_members,
    rooms=rooms,
    label="Cleaning Date",  # Pass variables needed by partial
    name="date",
    value=request.form.get('date', '')
)

@app.route('/cleaning_logs/edit/<int:log_id>', methods=['GET', 'POST'])
@role_required(['super_admin', 'staff'])
def edit_cleaning_log(log_id):
    log = CleaningLog.query.get_or_404(log_id)
    if request.method == 'POST':
        log.room_id = request.form.get('room_id')
        log.cleaned_by_id = request.form.get('cleaned_by_id')
        log.date = request.form.get('date')
        log.notes = request.form.get('notes')

        cleaner = Staff.query.get(log.cleaned_by_id)
        if not cleaner:
            flash('Invalid Staff ID', 'error')
            return render_template('edit_cleaning_log.html', log=log)

        if not log.date:
            flash('Date is required', 'error')
            return render_template('edit_cleaning_log.html', log=log)
        try:
            log.date = datetime.strptime(log.date, '%Y-%m-%d').date()
            db.session.commit()
            flash('Cleaning log updated successfully', 'success')
            return redirect(url_for('cleaning_logs'))
        except ValueError:
            flash('Invalid date format. Please use YYYY-MM-DD', 'error')
            return render_template('edit_cleaning_log.html', log=log)
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error editing cleaning log: {e}")
            flash('An error occurred while updating the log', 'error')
            return render_template('edit_cleaning_log.html', log=log)
    staff_members = Staff.query.all()
    return render_template('edit_cleaning_log.html', log=log, staff_members=staff_members)

@app.route('/cleaning_logs/delete/<int:log_id>', methods=['POST'])
@role_required(['super_admin'])
def delete_cleaning_log(log_id):
    log = CleaningLog.query.get_or_404(log_id)
    try:
        db.session.delete(log)
        db.session.commit()
        flash('Cleaning log deleted successfully', 'success')
        return redirect(url_for('cleaning_logs'))
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting cleaning log: {e}")
        flash('An error occurred while deleting the log', 'error')
        return redirect(url_for('cleaning_logs'))


from flask import jsonify, request
@app.route('/bar/mark-printed/<int:order_id>', methods=['POST'])
@login_required
def mark_order_printed(order_id):
    if not any(role.name in ['admin', 'super_admin', 'manager', 'bar_manager'] for role in current_user.roles):
        abort(403)
    order = BarOrder.query.get_or_404(order_id)
    db.session.delete(order)  # Delete instead of marking as printed
    db.session.commit()
    return jsonify({'success': True, 'order_id': order_id})


@app.route('/order/create', methods=['GET', 'POST'])
@login_required
def create_order():
    if request.method == 'POST':
        # Handle JSON POST from Vue
        if request.is_json:
            data = request.get_json()
            table_number = data.get('table_number')
            items = data.get('items', [])
        else:
            # Fallback for form POSTs (not used by your Vue code)
            table_number = request.form.get('table_number')
            items = []
            item_ids = request.form.getlist('item_id')
            quantities = request.form.getlist('quantity')
            for item_id, qty in zip(item_ids, quantities):
                items.append({'id': int(item_id), 'quantity': int(qty)})

        if not table_number or not items or all(i['quantity'] <= 0 for i in items):
            return jsonify({'success': False, 'error': 'Please select items and enter quantities.'})

        total_amount = 0
        order_items = []
        for item in items:
            bar_item = BarItem.query.get(item['id'])
            if not bar_item:
                continue
            qty = int(item['quantity'])
            if qty <= 0:
                continue
            subtotal = float(bar_item.price) * qty
            total_amount += subtotal
            order_items.append({'item': bar_item, 'quantity': qty, 'price': float(bar_item.price)})

        if total_amount <= 0 or not order_items:
            return jsonify({'success': False, 'error': 'Order must have at least one item.'})

        # Create the order
        order = BarOrder(
            user_id=current_user.id,
            table_number=table_number,
            total_amount=total_amount,
            status='pending',
            payment_status='pending'
        )
        db.session.add(order)
        db.session.flush()  # Get order.id before committing

        # Add order items
        for oi in order_items:
            order_item = OrderItem(
                order_id=order.id,
                item_id=oi['item'].id,
                quantity=oi['quantity'],
                price=oi['price']
            )
            db.session.add(order_item)

        db.session.commit()
        return jsonify({'success': True, 'order_id': order.id})

    # GET request - show order form
    items = BarItem.query.filter(BarItem.quantity > 0).all()
    return render_template('create_order.html', items=items)

@app.route('/order/pay/<int:order_id>', methods=['POST'])
@login_required
def pay_for_order(order_id):
    order = BarOrder.query.get_or_404(order_id)
    
    # Generate unique reference
    unique_reference = f"ORDER_{order_id}_{uuid.uuid4().hex[:8]}"
    order.payment_reference = unique_reference
    db.session.commit()

    # Initialize payment
    payment_data = initialize_paystack_payment(
        email=current_user.email,
        amount=order.total_amount,
        reference=unique_reference,
        metadata={'order_id': order.id},
        callback_type='barorder'
    )

    if payment_data and payment_data.get('status'):
        # Redirect user directly to Paystack
        return redirect(payment_data['data']['authorization_url'])
    
    flash('Payment initialization failed', 'error')
    return redirect(url_for('order_details', order_id=order_id))

def handle_order_payment(verification_data, reference):
    try:
        order = BarOrder.query.filter_by(payment_reference=reference).first()
        if not order:
            app.logger.error(f"Order not found: {reference}")
            return False

        if verification_data['data']['status'] != 'success':
            app.logger.error(f"Payment failed: {order.id}")
            return False

        # Update order status
        order.payment_status = 'paid'
        order.status = 'completed'
        order.paid_at = datetime.now(NIGERIA_TZ)

        # Update inventory
        for item in order.order_items:
            bar_item = db.session.get(BarItem, item.item_id)
            if bar_item:
                bar_item.quantity -= item.quantity
                
                # Create sale record (without order_id)
                sale = BarSale(
                    item_id=bar_item.id,
                    quantity_sold=item.quantity,
                    total_amount=item.price * item.quantity,
                    sale_time=datetime.now(NIGERIA_TZ)
                )
                db.session.add(sale)

        db.session.commit()
        
        # Send confirmation
        send_email(
            order.user.email,
            "Order Confirmed",
            f"Your order #{order.id} is confirmed! Total: ₦{order.total_amount:,.2f}"
        )
        
        return True
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Payment processing error: {str(e)}")
        return False

@app.route('/paystack/barorder_callback')
def paystack_barorder_callback():
    reference = request.args.get('reference')
    if not reference:
        app.logger.error("No reference provided in callback")
        return redirect(url_for('order_failed'))
    
    # Verify payment with Paystack
    verification_data = verify_payment(reference)
    if not verification_data or verification_data.get('data', {}).get('status') != 'success':
        app.logger.error("Paystack verification failed")
        return redirect(url_for('order_failed'))
    
    # Process the order
    if handle_order_payment(verification_data, reference):
        order = BarOrder.query.filter_by(payment_reference=reference).first()
        return redirect(url_for('order_confirmation', order_id=order.id))
    
    return redirect(url_for('order_failed'))





@app.route('/orders')
@login_required
def view_orders():
    if current_user.has_role('staff'):
        orders = BarOrder.query.order_by(BarOrder.created_at.desc()).all()
    else:
        orders = BarOrder.query.filter_by(user_id=current_user.id).all()
    
    return render_template('orders.html', orders=orders)

@app.route('/order/<int:order_id>')
@login_required
def order_details(order_id):
    order = BarOrder.query.get_or_404(order_id)
    if order.user_id != current_user.id and not current_user.has_role('staff'):
        abort(403)
    
    return render_template('order_details.html', order=order)

@app.route('/order/update/<int:order_id>', methods=['POST'])
@role_required(['staff', 'bar_manager'])
def update_order_status(order_id):
    order = BarOrder.query.get_or_404(order_id)
    new_status = request.form.get('status')
    
    if new_status in ['preparing', 'delivered', 'completed']:
        order.status = new_status
        db.session.commit()
        flash('Order status updated', 'success')
    
    return redirect(url_for('view_orders'))



# Payment Management
@app.route('/payments')
@role_required(['super_admin', 'staff'])
def payments():
    payments = Payment.query.all()
    return render_template('payments.html', payments=payments)

@app.route('/payments/add', methods=['GET', 'POST'])
@role_required(['super_admin', 'staff'])
def add_payment():
    if request.method == 'POST':
        booking_id = request.form.get('booking_id')
        amount = request.form.get('amount')
        payment_method = request.form.get('payment_method')
        booking = Booking.query.get_or_404(booking_id)
        if not amount or not payment_method:
            flash('Amount and payment method are required', 'error')
            return render_template('add_payment.html')
        try:
            amount = float(amount)
            if amount <= 0:
                flash('Invalid amount', 'error')
                return render_template('add_payment.html')
            if payment_method == 'Paystack':
                reference = f"payment_{datetime.now().strftime('%Y%m%d%H%M%S')}_{random.randint(1000, 9999)}"
                user = User.query.get(booking.user_id)
                email = user.email if user else None
                payment_data = initialize_paystack_payment(
                    email=email,
                    amount=amount,
                    reference=reference,
                    metadata={"booking_id": booking_id}
                )
                if not payment_data or not payment_data.get('status'):
                    flash('Failed to initialize payment', 'error')
                    return render_template('add_payment.html')
                session['payment_reference'] = reference
                return redirect(payment_data['data']['authorization_url'])
            else:
                payment = Payment(booking_id=booking_id, amount=amount, payment_method=payment_method)
                db.session.add(payment)
                db.session.commit()
                run_automations('payment_received', context={'payment': payment, 'user_id': current_user.id})
                flash('Payment added successfully', 'success')
                return redirect(url_for('payments'))
        except ValueError:
            flash('Invalid amount format', 'error')
            return render_template('add_payment.html')
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error adding payment: {e}")
            flash('An error occurred while adding the payment', 'error')
            return render_template('add_payment.html')
    return render_template('add_payment.html')




# ----- Payment Confirmation Route -----
@app.route('/payment/confirmation/<int:payment_id>')
@role_required(['user', 'super_admin', 'staff'])
def payment_confirmation(payment_id):
    payment = Payment.query.get_or_404(payment_id)
    booking = Booking.query.get(payment.booking_id)
    return render_template('payment_confirmation.html', 
                         payment=payment,
                         booking=booking)

# ----- Report Generation Route -----
@app.route('/reports/generate', methods=['GET', 'POST'])
@role_required(['super_admin', 'finance_admin'])
def generate_report():
    form = ReportForm()
    if form.validate_on_submit():
        try:
            # Create report object
            new_report = Report(
                report_type=form.report_type.data,
                parameters={
                    'start_date': form.start_date.data.isoformat(),
                    'end_date': form.end_date.data.isoformat(),
                    'format': form.format.data
                },
                generated_by=current_user.id
            )
            db.session.add(new_report)
            db.session.commit()
            
            flash('Report generation started', 'info')
            return redirect(url_for('reports'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Report generation error: {str(e)}")
            flash('Error initiating report generation', 'error')
    
    return render_template('reports/generate.html', form=form)

@app.route('/payment/callback')
def paystack_payment_callback():
    reference = session.get('payment_reference')
    if not reference:
        flash('Payment reference not found', 'error')
        return redirect(url_for('payments'))

    verification_data = verify_paystack_payment(reference)
    if not verification_data or not verification_data['status'] or verification_data['data']['status'] != 'success':
        flash('Payment verification failed', 'error')
        return redirect(url_for('payments'))

    metadata = verification_data['data']['metadata']
    booking_id = metadata.get('booking_id')
    amount = verification_data['data']['amount'] / 100

    if not booking_id:
        flash('Invalid booking ID in payment metadata', 'error')
        return redirect(url_for('payments'))
    try:
        payment = Payment(booking_id=booking_id, amount=amount, payment_method='Paystack', created_at=datetime.now(NIGERIA_TZ))
        db.session.add(payment)
        db.session.commit()
        flash('Payment added successfully', 'success')
        return redirect(url_for('payments'))
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error completing payment after verification: {e}")
        flash('An error occurred while completing the payment', 'error')
        return redirect(url_for('payments'))
    finally:
        session.pop('payment_reference', None)

@app.route('/payments/edit/<int:payment_id>', methods=['GET', 'POST'])
@role_required(['super_admin', 'staff'])
def edit_payment(payment_id):
    payment = Payment.query.get_or_404(payment_id)
    if request.method == 'POST':
        payment.booking_id = request.form.get('booking_id')
        payment.amount = request.form.get('amount')
        payment.payment_method = request.form.get('payment_method')
        booking = Booking.query.get_or_404(payment.booking_id)
        if not payment.amount or not payment.payment_method:
            flash('Amount and payment method are required', 'error')
            return render_template('edit_payment.html', payment=payment)
        try:
            payment.amount = float(payment.amount)
            if payment.amount <= 0:
                flash('Invalid amount', 'error')
                return render_template('edit_payment.html', payment=payment)
            db.session.commit()
            flash('Payment updated successfully', 'success')
            return redirect(url_for('payments'))
        except ValueError:
            flash('Invalid amount format', 'error')
            return render_template('edit_payment.html', payment=payment)
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error editing payment: {e}")
            flash('An error occurred while updating the payment', 'error')
            return render_template('edit_payment.html', payment=payment)
    return render_template('edit_payment.html', payment=payment)

@app.route('/payments/delete/<int:payment_id>', methods=['POST'])
@role_required(['super_admin'])
def delete_payment(payment_id):
    payment = Payment.query.get_or_404(payment_id)
    try:
        db.session.delete(payment)
        db.session.commit()
        flash('Payment deleted successfully', 'success')
        return redirect(url_for('payments'))
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting payment: {e}")
        flash('An error occurred while deleting the payment', 'error')
        return redirect(url_for('payments'))

# Room Image Management
def save_image(image):
    if not image or not allowed_file(image.filename):
        return None, "Invalid file or file type"

    try:
        filename = secure_filename(image.filename)
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        image.save(image_path)

        kind = filetype.guess(image_path)
        if kind and kind.mime.startswith('image'):
            return filename, None
        else:
            os.remove(image_path)
            return None, "Uploaded file is not a valid image"

    except Exception as e:
        app.logger.error(f"Error saving image: {e}")
        return None, "Failed to save image"

@app.route('/room_images/<int:room_id>', methods=['GET', 'POST'])
@role_required(['super_admin'])
def room_images(room_id):
    room = Room.query.get_or_404(room_id)
    if request.method == 'POST':
        images = request.files.getlist('images')
        primary_image_id = request.form.get('primary_image')

        for image in images:
            filename, error = save_image(image)
            if filename:
                room_image = RoomImage(room_id=room_id, filename=filename)
                db.session.add(room_image)
            elif error:
                flash(f"Error with image: {error}", 'error')

        db.session.commit()

        if primary_image_id:
            RoomImage.query.filter_by(room_id=room_id).update({RoomImage.is_primary: False})
            primary_image = RoomImage.query.get(primary_image_id)
            if primary_image:
                primary_image.is_primary = True
                db.session.commit()
            else:
                flash("Primary image ID invalid", 'error')

        flash('Images uploaded successfully', 'success')
        return redirect(url_for('room_images', room_id=room_id))

    room_images = RoomImage.query.filter_by(room_id=room_id).all()
    return render_template('room_images.html', room=room, room_images=room_images)

@app.route('/room_images/delete/<int:image_id>', methods=['POST'])
@role_required(['super_admin'])
def delete_room_image(image_id):
    image = RoomImage.query.get_or_404(image_id)
    room_id = image.room_id
    try:
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], image.filename)
        if os.path.exists(image_path):
            os.remove(image_path)
        db.session.delete(image)
        db.session.commit()
        flash('Image deleted successfully', 'success')
        return redirect(url_for('room_images', room_id=room_id))
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting room image: {e}")
        flash('An error occurred while deleting the image', 'error')
        return redirect(url_for('room_images', room_id=room_id))

# Maintenance Request

@app.route('/maintenance_requests', methods=['GET', 'POST'])
@role_required(['user', 'super_admin', 'staff'])
@login_required
def maintenance_requests():
    if request.method == 'POST':
        room_id = request.form.get('room_id')
        issue_type = request.form.get('issue_type')
        description = request.form.get('description')
        priority = request.form.get('priority')
        notes = request.form.get('notes')

        if not room_id or not issue_type or not description:
            flash('Room, issue type, and description are required.', 'danger')
        else:
            try:
                req = MaintenanceRequest(
                    room_id=room_id,
                    issue_type=issue_type,
                    description=description,
                    priority=priority or 'Medium',
                    notes=notes,
                    status='Open',
                    request_time=datetime.now(NIGERIA_TZ),
                    created_at=datetime.now(NIGERIA_TZ),
                    reported_by_id=current_user.id
                )
                db.session.add(req)
                db.session.commit()
                
                run_automations('maintenance_requested', context={'request': req, 'user_id': current_user.id})
                flash('Maintenance request submitted successfully', 'success')
                return redirect(url_for('maintenance_requests'))
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Error submitting maintenance request: {e}")
                flash('An error occurred while submitting your request. Please try again.', 'error')

    # Show all requests for super_admin/staff, only own for user
    if current_user.has_role('super_admin') or current_user.has_role('staff'):
        requests = MaintenanceRequest.query.order_by(MaintenanceRequest.created_at.desc()).all()
    else:
        requests = MaintenanceRequest.query.filter_by(reported_by_id=current_user.id).order_by(MaintenanceRequest.created_at.desc()).all()

    return render_template('maintenance_requests.html', requests=requests)



@app.route('/maintenance_requests/create', methods=['GET', 'POST'])
@role_required(['user', 'super_admin', 'staff'])
@login_required
def create_maintenance_request():
    rooms = Room.query.all()
    if request.method == 'POST':
        room_id = request.form.get('room_id')
        issue_type = request.form.get('issue_type')
        description = request.form.get('description')
        priority = request.form.get('priority')
        notes = request.form.get('notes')

        # Validate required fields
        if not (room_id and issue_type and description):
            flash('Room, issue type, and description are required.', 'danger')
            return render_template('create_maintenance_request.html', rooms=rooms)

        req = MaintenanceRequest(
            room_id=room_id,
            issue_type=issue_type,
            description=description,
            priority=priority or 'Medium',
            notes=notes,
            status='Open',
            request_time=datetime.now(NIGERIA_TZ),
            created_at=datetime.now(NIGERIA_TZ),
            reported_by_id=current_user.id
        )
        db.session.add(req)
        db.session.commit()
        
        run_automations('maintenance_requested', context={'request': req, 'user_id': current_user.id})
        flash('Maintenance request submitted!', 'success')
        if  current_user.has_role('super_admin') or current_user.has_role('staff'):
            return redirect(url_for('maintenance_requests'))
        else:
            # Redirect to home for regular users
            flash('Your request has been submitted and will be reviewed shortly.', 'info')
            return redirect(url_for('home'))
    return render_template('create_maintenance_request.html', rooms=rooms)


@app.route('/maintenance_requests/view/<int:request_id>')
@role_required(['super_admin', 'staff', 'user'])
@login_required
def view_maintenance_request(request_id):
    req = MaintenanceRequest.query.get_or_404(request_id)
    return render_template('view_maintenance_request.html', req=req)


@app.route('/maintenance_requests/edit/<int:request_id>', methods=['GET', 'POST'])
@role_required(['super_admin', 'staff', 'user'])
@login_required
def edit_maintenance_request(request_id):
    req = MaintenanceRequest.query.get_or_404(request_id)
    rooms = Room.query.all()
    if request.method == 'POST':
        req.room_id = request.form.get('room_id')
        req.issue_type = request.form.get('issue_type')
        req.description = request.form.get('description')
        req.priority = request.form.get('priority')
        req.notes = request.form.get('notes')
        db.session.commit()
        run_automations('maintenance_updated', context={'request': req, 'user_id': current_user.id})
        flash('Maintenance request updated successfully!', 'success')
        return redirect(url_for('view_maintenance_request', request_id=req.id))
    return render_template('edit_maintenance_request.html', request_obj=req, rooms=rooms)

@app.route('/maintenance_requests/delete/<int:request_id>', methods=['POST'])
@role_required(['super_admin', 'staff'])
def delete_maintenance_request(request_id):
    request_obj = MaintenanceRequest.query.get_or_404(request_id)
    try:
        db.session.delete(request_obj)
        db.session.commit()
        run_automations('maintenance_deleted', context={'request': request_obj, 'user_id': current_user.id})
        flash('Maintenance request deleted successfully', 'success')
        return redirect(url_for('maintenance_requests'))
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting maintenance request: {e}")
        flash('An error occurred while deleting the request', 'error')
        return redirect(url_for('maintenance_requests'))

@app.route('/maintenance_requests/resolve/<int:request_id>', methods=['POST'])
@role_required(['super_admin', 'staff'])
def resolve_maintenance_request(request_id):
    request_obj = MaintenanceRequest.query.get_or_404(request_id)
    request_obj.status = 'Resolved'
    request_obj.resolved_at = datetime.now()
    db.session.commit()
    run_automations('maintenance_resolved', context={'request': request_obj, 'user_id': current_user.id})
    try:
        db.session.commit()
        flash('Maintenance request marked as resolved', 'success')
        return redirect(url_for('maintenance_requests'))
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error resolving maintenance request: {e}")
        flash('An error occurred while resolving the request', 'error')
        return redirect(url_for('maintenance_requests'))

# Error Handling
@app.errorhandler(HTTPException)
def handle_exception(e):
    app.logger.error(f"HTTPException: {e}")
    response = e.get_response()
    response.data = json.dumps({
        "code": e.code,
        "name": e.name,
        "description": e.description,
    })
    response.content_type = "application/json"
    return response

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/cookies')
def cookies():
    return render_template('cookies.html')

@app.errorhandler(HTTPException)
def handle_exception(e):
    app.logger.error(f"HTTPException: {e}")
    response = e.get_response()
    response.data = json.dumps({
        "code": e.code,
        "name": e.name,
        "description": e.description,
    })
    response.content_type = "application/json"
    return response

def calculate_occupancy_rate():
    total_rooms = Room.query.count()
    if total_rooms == 0:
        return 0.0
    today = datetime.today().date()
    occupied_rooms = Booking.query.filter(
        Booking.check_in_date <= today,
        Booking.check_out_date >= today,
        Booking.check_in_status == 'Checked-in'  # Add status filter
    ).count()
    return (occupied_rooms / total_rooms) * 100

def get_daily_revenue():
    today = datetime.today().date()
    total = db.session.query(func.sum(Payment.amount)).filter(
        func.date(Payment.created_at) == today
    ).scalar()
    return total or 0.0


# =======================
# ADMIN DASHBOARD ROUTE
# =======================

@app.route('/admin/activity-logs')
@admin_required
def activity_logs():
    page = request.args.get('page', 1, type=int)
    logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).paginate(page=page, per_page=20)
    
    return render_template('admin/activity_logs.html', 
        logs=logs,
        title='Full Activity Logs'
    )

@app.route('/admin/dashboard')
@role_required(['super_admin'])
def admin_dashboard():
    from sqlalchemy import func
    from collections import defaultdict

    # Room status calculations
    total_rooms = Room.query.count()
    occupied_rooms = Room.query.filter_by(status='occupied').count()
    available_rooms = Room.query.filter_by(status='available').count()
    maintenance_rooms = Room.query.filter_by(status='maintenance').count()

    # Occupancy rate calculation
    occupancy_rate = (occupied_rooms / total_rooms) * 100 if total_rooms > 0 else 0

    today = datetime.now(NIGERIA_TZ).date()

    # Revenue calculations
    booking_revenue = db.session.query(func.sum(Payment.amount)).filter(Payment.status == 'success').scalar() or 0
   
    bar_orders_revenue = db.session.query(func.sum(BarOrder.total_amount)).filter(BarOrder.payment_status == 'paid').scalar() or 0
    # If you want to include inventory usage as revenue, uncomment below:
    # inventory_usage_revenue = db.session.query(func.sum(InventoryUsage.quantity_used * StoreInventory.unit_cost)).join(StoreInventory).scalar() or 0

    total_revenue = float(booking_revenue) + float(bar_orders_revenue) # + float(inventory_usage_revenue)

    # Daily revenue (today, bookings only)
   # Daily revenue (today, bookings + bar orders)
    daily_booking_revenue = db.session.query(func.sum(Payment.amount)).filter(
        func.date(Payment.created_at) == today,
        Payment.status == 'success'
    ).scalar() or 0
    daily_bar_orders_revenue = db.session.query(func.sum(BarOrder.total_amount)).filter(
        func.date(BarOrder.created_at) == today,
        BarOrder.payment_status == 'paid'
    ).scalar() or 0
    daily_revenue = float(daily_booking_revenue) + float(daily_bar_orders_revenue)

    daily_revenue_paid = db.session.query(func.sum(Payment.amount)).filter(
        func.date(Payment.created_at) == today,
        Payment.status == 'success'
    ).scalar() or 0

    # Today's Bookings (ONLY PAID)
    new_bookings = Booking.query.filter(
        func.date(Booking.check_in_date) == today,
        Booking.payment_status == 'paid'
    ).order_by(Booking.check_in_date.asc()).count()

    # Today's check-ins
    checkins_today = Booking.query.filter(
        func.date(Booking.check_in_date) == today,
        Booking.check_in_status == 'Checked-in'
    ).count()

    # Today's check-outs
    checkouts_today = Booking.query.filter(
        func.date(Booking.check_out_date) == today,
        Booking.check_in_status == 'Checked-out'
    ).count()

    # Revenue chart data (last 7 days)
    revenue_data = []
    revenue_labels = []
    for i in range(6, -1, -1):
        day = today - timedelta(days=i)
        daily_total = db.session.query(func.sum(Payment.amount)).filter(
            func.date(Payment.created_at) == day
        ).scalar() or 0
        revenue_data.append(float(daily_total))
        revenue_labels.append(day.strftime('%b %d'))

    # Recent activities
    recent_activities = ActivityLog.query.order_by(
        ActivityLog.timestamp.desc()
    ).limit(10).all()

    yesterday = today - timedelta(days=1)
    last_week = today - timedelta(days=7)

    # Daily revenue change
    today_revenue = db.session.query(func.sum(Payment.amount)).filter(
        func.date(Payment.created_at) == today,
        Payment.status == 'success'
    ).scalar() or 0

    yesterday_revenue = db.session.query(func.sum(Payment.amount)).filter(
        func.date(Payment.created_at) == yesterday
    ).scalar() or 0

    daily_revenue_change = 0
    if yesterday_revenue > 0:
        daily_revenue_change = round(((today_revenue - yesterday_revenue) / yesterday_revenue) * 100, 1)

    # Total revenue change (month-over-month)
    current_month_start = today.replace(day=1)
    prev_month_end = current_month_start - timedelta(days=1)
    prev_month_start = prev_month_end.replace(day=1)

    current_month_revenue = db.session.query(func.sum(Payment.amount)).filter(
        Payment.created_at >= current_month_start
    ).scalar() or 0

    prev_month_revenue = db.session.query(func.sum(Payment.amount)).filter(
        Payment.created_at.between(prev_month_start, prev_month_end)
    ).scalar() or 0

    total_revenue_change = 0
    if prev_month_revenue > 0:
        total_revenue_change = round(((current_month_revenue - prev_month_revenue) / prev_month_revenue) * 100, 1)

    # New bookings change
    today_bookings_count = Booking.query.filter(
        func.date(Booking.created_at) == today
    ).count()

    yesterday_bookings_count = Booking.query.filter(
        func.date(Booking.created_at) == yesterday
    ).count()

    new_bookings_change = 0
    if yesterday_bookings_count > 0:
        new_bookings_change = round(((today_bookings_count - yesterday_bookings_count) / yesterday_bookings_count) * 100, 1)

    # Check-ins change
    today_checkins_count = Booking.query.filter(
        func.date(Booking.check_in_date) == today,
        Booking.check_in_status == 'Checked-in'
    ).count()

    yesterday_checkins_count = Booking.query.filter(
        func.date(Booking.check_in_date) == yesterday,
        Booking.check_in_status == 'Checked-in'
    ).count()

    checkins_today_change = 0
    if yesterday_checkins_count > 0:
        checkins_today_change = round(((today_checkins_count - yesterday_checkins_count) / yesterday_checkins_count) * 100, 1)

    # Guests This Week (last 7 days)
    guests_by_day = defaultdict(int)
    for i in range(6, -1, -1):
        day = today - timedelta(days=i)
        guests = Booking.query.filter(
            func.date(Booking.check_in_date) == day
        ).count()
        guests_by_day[day.strftime('%a')] = guests

    # Monthly Bookings (last 6 months)
    monthly_bookings = []
    monthly_labels = []
    for i in range(5, -1, -1):
        month_date = today - timedelta(days=30*i)
        month_start = month_date.replace(day=1)
        month_end = (month_start + timedelta(days=32)).replace(day=1) - timedelta(days=1)

        count = Booking.query.filter(
            Booking.created_at.between(month_start, month_end)
        ).count()

        monthly_bookings.append(count)
        monthly_labels.append(month_start.strftime('%b'))

    # Bookings by Platform
    booking_sources = {
        'Direct': Booking.query.filter_by(booking_source='direct').count(),
        'Website': Booking.query.filter_by(booking_source='website').count(),
        'Mobile App': Booking.query.filter_by(booking_source='mobile').count(),
        'Travel Agent': Booking.query.filter_by(booking_source='agent').count(),
        'OTA': Booking.query.filter_by(booking_source='ota').count()
    }

    # User Activity (engagement based on activity logs)
    user_activity = []
    active_users = db.session.query(
        User.id,
        func.count(ActivityLog.id).label('activity_count')
    ).join(ActivityLog).filter(
        ActivityLog.timestamp >= last_week
    ).group_by(User.id).all()

    for user in active_users:
        engagement_level = min(5, user.activity_count // 5)
        activity_freq = min(10, user.activity_count // 2)
        user_activity.append({
            'x': activity_freq,
            'y': engagement_level,
            'r': 5 + user.activity_count,
            'label': f"User {user.id}"
        })

    # Feature Usage (based on activity log types)
    feature_usage = {
        'labels': ['Booking', 'Check-in', 'Payment', 'Room Service', 'Housekeeping', 'Support'],
        'data': [
            ActivityLog.query.filter(ActivityLog.title.like('%Booking%')).count(),
            ActivityLog.query.filter(ActivityLog.title.like('%Check-in%')).count(),
            ActivityLog.query.filter(ActivityLog.title.like('%Payment%')).count(),
            ActivityLog.query.filter(ActivityLog.title.like('%Room Service%')).count(),
            ActivityLog.query.filter(ActivityLog.title.like('%Housekeeping%')).count(),
            ActivityLog.query.filter(ActivityLog.title.like('%Support%')).count()
        ]
    }

    # Occupancy Rate (last 7 days)
    occupancy_rates = []
    occupancy_labels = []
    for i in range(6, -1, -1):
        day = today - timedelta(days=i)
        occupied = Booking.query.filter(
            Booking.check_in_date <= day,
            Booking.check_out_date > day,
            Booking.check_in_status == 'Checked-in'
        ).count()
        rate = (occupied / total_rooms) * 100 if total_rooms > 0 else 0
        occupancy_rates.append(round(rate, 1))
        occupancy_labels.append(day.strftime('%a'))

    # Maintenance requests
    pending_tasks = MaintenanceRequest.query.filter_by(status='pending').count()
    notifications = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()

    # Activity icons/colors
    for activity in recent_activities:
        if "Booking" in activity.title:
            activity.icon_class = "bi bi-journal-plus"
            activity.icon_bg_color = "bg-light-blue"
            activity.icon_text_color = "text-blue"
        elif "Check-in" in activity.title:
            activity.icon_class = "bi bi-door-open"
            activity.icon_bg_color = "bg-light-green"
            activity.icon_text_color = "text-green"
        elif "Payment" in activity.title:
            activity.icon_class = "bi bi-credit-card"
            activity.icon_bg_color = "bg-light-purple"
            activity.icon_text_color = "text-purple"
        else:
            activity.icon_class = "bi bi-activity"
            activity.icon_bg_color = "bg-light-orange"
            activity.icon_text_color = "text-orange"

    # Calculate average rating
    avg_rating = db.session.query(db.func.avg(Rating.rating)).scalar() or 0.0
    rating_count = Rating.query.count()

    booking = Booking.query.all()
    # Revenue breakdown for template
    revenue_breakdown = {
        'Bookings': float(booking_revenue),
        'Bar Orders': float(bar_orders_revenue),
    }
    return render_template('admin_dashboard.html',
        occupancy_rate=round(occupancy_rate, 1),
        total_rooms=total_rooms,
        average_rating=round(avg_rating, 1),
        rating_count=rating_count,
        occupied_rooms=occupied_rooms,
        available_rooms=available_rooms,
        maintenance_rooms=maintenance_rooms,
        pending_tasks=pending_tasks,
        revenue_labels=revenue_labels,
        revenue_data=revenue_data,
        recent_activities=recent_activities,
        daily_revenue_paid=daily_revenue_paid,
        daily_revenue=daily_revenue,
        total_revenue=total_revenue,
        new_bookings=new_bookings,
        checkins_today=checkins_today,
        checkouts_today=checkouts_today,
        daily_revenue_change=daily_revenue_change,
        total_revenue_change=total_revenue_change,
        new_bookings_change=new_bookings_change,
        checkins_today_change=checkins_today_change,
        guests_data=list(guests_by_day.values()),
        monthly_bookings=monthly_bookings,
        booking_sources=booking_sources,
        user_activity=user_activity,
        feature_usage=feature_usage,
        occupancy_rates=occupancy_rates,
        days=list(guests_by_day.keys()),
        monthly_labels=monthly_labels,
        occupancy_labels=occupancy_labels,
        booking=booking,revenue_breakdown=revenue_breakdown)
def get_revenue_labels():
    today = datetime.today().date()
    return [(today - timedelta(days=i)).strftime('%b %d') for i in range(6, -1, -1)]

def get_revenue_data():
    data = []
    today = datetime.today().date()
    for i in range(6, -1, -1):
        day = today - timedelta(days=i)
        total = db.session.query(func.sum(Payment.amount)).filter(
            func.date(Payment.created_at) == day
        ).scalar() or 0
        data.append(float(total))
    return data




# Notification Routes
@app.route('/notifications')
@login_required
def notifications():
    page = request.args.get('page', 1, type=int)
    user_notifications = Notification.query.filter_by(user_id=current_user.id)\
        .order_by(Notification.created_at.desc()).paginate(page=page, per_page=10)
    return render_template('notifications.html', notifications=user_notifications.items, pagination=user_notifications)

@app.route('/notification/<int:notification_id>')
@login_required
def notification_detail(notification_id):
    notification = Notification.query.get_or_404(notification_id)
    if not notification.is_read:
        notification.is_read = True
        db.session.commit()
    return render_template('notification_detail.html', notification=notification)

@app.route('/notification/<int:notification_id>/mark-read', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    notification = Notification.query.get_or_404(notification_id)
    if not notification.is_read:
        notification.is_read = True
        db.session.commit()
    return jsonify({'success': True})

@app.route('/notifications/all')
@login_required
def all_notifications():
    notifications_all = Notification.query.filter_by(user_id=current_user.id)\
        .order_by(Notification.created_at.desc())\
        .all()
    return render_template('notifications_all.html', notifications_all= notifications_all)



@app.route('/notifications/create', methods=['GET', 'POST'])
@admin_required
def create_notification():
    form = NotificationForm()
    
    # Populate dynamic choices
    form.roles.choices = [(r.id, r.name) for r in Role.query.order_by(Role.name).all()]
    form.custom_users.choices = [(u.id, f"{u.first_name} <{u.email}>") 
                               for u in User.query.order_by(User.email).all()]
    
    if form.validate_on_submit():
        recipients = []
        now = datetime.now(NIGERIA_TZ)
        
        # Apply filters
        if form.send_to.data == 'all':
            recipients = User.query.all()
            
        elif form.send_to.data == 'role':
            role_ids = form.roles.data
            recipients = User.query.join(User.roles).filter(
                Role.id.in_(role_ids)
            ).all()
            
        elif form.send_to.data == 'custom':
            recipients = User.query.filter(
                User.id.in_(form.custom_users.data)
            ).all()
            
        elif form.send_to.data == 'new_users':
            threshold = now - timedelta(days=form.days_threshold.data)
            recipients = User.query.filter(
                User.created_at >= threshold
            ).all()
            
        elif form.send_to.data == 'frequent_customers':
            recipients = db.session.query(User).join(Booking).group_by(User.id).having(
                db.func.count(Booking.id) >= form.min_bookings.data
            ).all()
            
        elif form.send_to.data == 'inactive_users':
            threshold = now - timedelta(days=form.inactive_days.data)
            recipients = User.query.filter(
                User.last_login <= threshold
            ).all()
            
        elif form.send_to.data == 'high_value':
            recipients = db.session.query(User).join(Booking).group_by(User.id).having(
                db.func.sum(Booking.total_amount) >= form.min_spending.data
            ).all()
            
        elif form.send_to.data == 'room_type':
            recipients = db.session.query(User).join(Booking).join(Room).filter(
                Room.room_type.in_(form.room_types.data)
            ).distinct().all()
            
        elif form.send_to.data == 'no_bookings':
            subquery = db.session.query(Booking.user_id).distinct()
            recipients = User.query.filter(
                ~User.id.in_(subquery)
            ).all()
            
        elif form.send_to.data == 'recent_activity':
            threshold = now - timedelta(days=form.last_activity_days.data)
            recipients = db.session.query(User).filter(
                db.or_(
                    User.last_login >= threshold,
                    db.session.query(Booking).filter(
                        Booking.user_id == User.id,
                        Booking.created_at >= threshold
                    ).exists()
                )
            ).all()

        # Create notifications
        if recipients:
            notifications = [Notification(
                title=form.title.data,
                message=form.message.data,
                category=form.category.data,
                expires_at=form.expires_at.data,
                user_id=user.id
            ) for user in recipients]
            
            db.session.add_all(notifications)
            db.session.commit()
            flash(f'Notification sent to {len(recipients)} users', 'success')
        else:
            flash('No users match the selected criteria', 'warning')
            
        return redirect(url_for('notifications'))
    
    return render_template('notifications/create.html', form=form)



@app.route('/automations', methods=['GET', 'POST'])
@role_required(['super_admin'])
def automations():
    form = AutomationForm()
    if form.validate_on_submit():
        automation = Automation(
            name=form.name.data,
            trigger_type=form.trigger_type.data,
            action_type=form.action_type.data,
            is_active=form.is_active.data,
            trigger_config={},
            action_config={}
        )
        db.session.add(automation)
        db.session.commit()
        flash('Automation rule created', 'success')
        return redirect(url_for('automations'))
    
    rules = Automation.query.order_by(Automation.created_at.desc()).all()
    return render_template('automations/list.html', form=form, rules=rules)

@app.route('/automations/<int:rule_id>/toggle', methods=['POST'])
@role_required(['super_admin'])
def toggle_automation(rule_id):
    rule = Automation.query.get_or_404(rule_id)
    rule.is_active = not rule.is_active
    db.session.commit()
    return jsonify({'status': 'success', 'is_active': rule.is_active})

@app.route('/reports', methods=['GET', 'POST'])
@role_required(['super_admin', 'finance_admin'])
def reports():
    form = ReportForm()
    if form.validate_on_submit():
        report = Report(
            report_type=form.report_type.data,
            parameters={
                'start_date': form.start_date.data.isoformat(),
                'end_date': form.end_date.data.isoformat(),
                'format': form.report_format.data
            },
            generated_by=current_user.id
        )
        db.session.add(report)
        db.session.commit()
        
        Thread(target=generate_report_task, args=(report.id,)).start()
        
        flash('Report generation started. Check back later.', 'info')
        return redirect(url_for('reports'))
    
    user_reports = current_user.reports.order_by(Report.created_at.desc()).all()
    return render_template('reports/list.html', form=form, reports=user_reports)

def generate_report_task(report_id):
    with app.app_context():
        report = Report.query.get(report_id)
        try:
            report.status = 'processing'
            db.session.commit()

            # Get form parameters
            start_date = datetime.fromisoformat(report.parameters['start_date'])
            end_date = datetime.fromisoformat(report.parameters['end_date'])
            report_format = report.parameters['format']

            # Query data based on report type
            if report.report_type == 'daily':
                data = Booking.query.filter(
                    func.date(Booking.created_at) == start_date.date()
                ).all()
            elif report.report_type == 'monthly':
                data = Booking.query.filter(
                    extract('month', Booking.created_at) == start_date.month,
                    extract('year', Booking.created_at) == start_date.year
                ).all()
            else:  # custom
                data = Booking.query.filter(
                    Booking.created_at.between(start_date, end_date)
                ).all()

            # Generate file
            report_dir = os.path.join(app.root_path, 'static/reports')
            os.makedirs(report_dir, exist_ok=True)
            filename = f"report_{report_id}.{report_format}"
            filepath = os.path.join(report_dir, filename)

            if report_format == 'csv':
                with open(filepath, 'w') as f:
                    writer = csv.writer(f)
                    writer.writerow(['ID', 'Guest', 'Room', 'Check-In', 'Check-Out', 'Amount'])
                    for booking in data:
                        writer.writerow([
                            booking.id,
                            booking.user.username,
                            booking.room.name,
                            booking.check_in_date,
                            booking.check_out_date,
                            booking.total_amount
                        ])
            elif report_format == 'pdf':
                # Implement PDF generation using ReportLab or similar
                pass  # Add PDF generation logic

            report.file_path = f"/static/reports/{filename}"
            report.status = 'completed'
            report.completed_at = datetime.now(NIGERIA_TZ)
            db.session.commit()

        except Exception as e:
            report.status = 'failed'
            db.session.commit()
            app.logger.error(f"Report generation failed: {e}")

@app.route('/reports/download/<int:report_id>')
@role_required(['super_admin', 'finance_admin'])
def download_report(report_id):
    report = Report.query.get_or_404(report_id)
    if report.status != 'completed':
        abort(404)
    return send_from_directory(
        os.path.join(app.root_path, 'static/reports'),
        os.path.basename(report.file_path),
        as_attachment=True
    )
from datetime import datetime, timezone, timedelta
from flask import abort



@app.route('/admin/register/<token>', methods=['GET', 'POST'])
def admin_register(token):
    try:
        # Verify registration token
        token_record = AdminRegistrationToken.query.filter_by(token=token).first()
        if not token_record:
            abort(404, description="Invalid registration token")
        
        # Handle timezone conversion
        current_time = datetime.now(NIGERIA_TZ)
        expires_at = token_record.expires_at
        
        # Convert to aware datetime if stored as naive (SQLite case)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        
        if expires_at < current_time:
            abort(403, description="Registration token has expired")

        form = AdminRegistrationForm()
        
        if form.validate_on_submit():
            email = form.email.data.strip().lower()
            password = form.password.data

            # Check for existing user
            if User.query.filter(func.lower(User.email) == email).first():
                flash('Email already registered', 'error')
                return redirect(url_for('admin_register', token=token))

            # Create new admin user
            new_admin = User(
                username=email.split('@')[0],
                email=email,
                password=generate_password_hash(password),
                status='pending',
                created_at=datetime.now(NIGERIA_TZ)
            )
            
            # Assign base admin role
            admin_role = Role.query.filter_by(name='admin').first()
            if admin_role:
                new_admin.roles.append(admin_role)
            
            db.session.add(new_admin)
            db.session.commit()
            
            # Notify super admins
            Notification.send_admin_approval_notification(new_admin)
            
            flash('Admin registration submitted for approval', 'success')
            return redirect(url_for('admin_login'))
        form = AdminRegistrationForm() 
            
        return render_template('admin_register.html', 
                             form=form, 
                             token=token,
                             expires_at=expires_at.astimezone().strftime('%Y-%m-%d %H:%M %Z'))
            
    except Exception as e:
        app.logger.error(f"Admin registration error: {str(e)}")
        flash('Error processing registration', 'error')
        return redirect(url_for('home'))




@app.route('/create-first-admin', methods=['GET', 'POST'])
@csrf.exempt  # Only if you're not using CSRF protection
def create_first_admin():
    # Check if any super admin exists
    if User.query.join(User.roles).filter(Role.name == 'super_admin').count() > 0:
        flash('A super admin already exists. Please log in.', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        phone_number = request.form.get('phone_number', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        # Validate required fields
        if not all([first_name, last_name, phone_number, email, password]):
            flash('All fields are required.', 'danger')
            return render_template('create_first_admin.html')

        # Check for existing email or username
        if User.query.filter_by(email=email).first():
            flash('Email already exists.', 'danger')
            return render_template('create_first_admin.html')
        if User.query.filter_by(first_name=first_name).first():
            flash('First name already exists.', 'danger')
            return render_template('create_first_admin.html')
        if User.query.filter_by(last_name=last_name).first():
            flash('Last name already exists.', 'danger')
            return render_template('create_first_admin.html')

        # Get or create super_admin role
        super_admin_role = Role.query.filter_by(name='super_admin').first()
        if not super_admin_role:
            super_admin_role = Role(name='super_admin', description='Super Administrator')
            db.session.add(super_admin_role)
            db.session.commit()

        try:
            user = User(
                first_name=first_name,
                last_name=last_name,
                phone_number=phone_number,
                email=email,
                password=generate_password_hash(password),
                status='approved',
                is_main_admin=True,
                email_verified=True
            )
            user.roles.append(super_admin_role)
            db.session.add(user)
            db.session.commit()
            flash('Super admin account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash('A user with this information already exists.', 'danger')
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating super admin: {str(e)}', 'danger')

    return render_template('create_first_admin.html')


@app.route('/approve_admin/<int:admin_id>', methods=['POST'])
@role_required(['super_admin'])
def approve_admin(admin_id):
    try:
        admin = User.query.get_or_404(admin_id)
        selected_roles = request.form.getlist('roles')
        
        if not selected_roles:
            flash('At least one role must be selected', 'error')
            return redirect(url_for('admin_dashboard'))

        # Clear existing roles and assign new ones
        admin.roles = []
        for role_name in selected_roles:
            role = Role.query.filter_by(name=role_name).first()
            if role:
                admin.roles.append(role)
        
        # Add default user role if missing
        if not any(r.name == 'user' for r in admin.roles):
            user_role = Role.query.filter_by(name='user').first()
            if user_role:
                admin.roles.append(user_role)

        admin.status = 'approved'
        admin.approved_at = datetime.now(NIGERIA_TZ)
        admin.approved_by = current_user.id
        
        db.session.commit()
        
        # Send notification email
        send_email(
            to_email=admin.email,
            subject="Admin Account Approved",
            body=f"""Your admin account has been approved with roles: {", ".join(selected_roles)}.
            You can now access the admin dashboard at {url_for('admin_dashboard', _external=True)}"""
        )
        
        flash(f'{admin.email} approved with roles: {", ".join(selected_roles)}', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Admin approval error: {str(e)}")
        flash(f'Approval failed: {str(e)}', 'danger')
    
    return redirect(url_for('admin_dashboard'))


# API Key Management Routes
@app.route('/generate_key', methods=['POST',  ])
@login_required
@role_required('api_management')
def api_generate_key():
    try:
        new_key = APIKey(
            value=secrets.token_urlsafe(32),
            owner_id=current_user.id,
            expires_at=datetime.now(NIGERIA_TZ) + timedelta(days=30)
        )
        db.session.add(new_key)
        db.session.commit()
        flash('New API key generated!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Key generation failed: {str(e)}', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/revoke_key/<int:key_id>', methods=['POST'])
@login_required
@role_required('api_management')
def revoke_key(key_id):
    try:
        key = APIKey.query.get_or_404(key_id)
        key.is_revoked = True
        key.revoked_at = datetime.now(NIGERIA_TZ)
        db.session.commit()
        flash('Key revoked successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Key revocation failed: {str(e)}', 'danger')
    return redirect(url_for('admin_dashboard'))



# ADMIN REGISTRATION ROUTES
@app.route('/admin/generate-reg-token', methods=['GET', 'POST'])
@admin_required
def generate_reg_token():
    try:
        # Clear existing tokens
        AdminRegistrationToken.query.delete()
        
        # Create new token OBJECT
        new_token = AdminRegistrationToken(
            token=secrets.token_urlsafe(32),
            generated_by=current_user.id,
            expires_at=datetime.now(NIGERIA_TZ) + timedelta(hours=24))
        
        db.session.add(new_token)
        db.session.commit()
        
        flash('New registration token generated', 'success')
        return redirect(url_for('admin_dashboard'))
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error generating token: {str(e)}', 'error')
        return redirect(url_for('admin_dashboard'))
    
@app.route('/admin/approvals', methods=['GET', 'POST'])
@admin_required
@role_required(['super_admin', 'hr'])
def admin_approvals():
    if request.method == 'POST':
        admin_id = request.form.get('admin_id')
        action = request.form.get('action')
        admin = User.query.get_or_404(admin_id)
        
        if action == 'approve':
            admin.status = 'approved'
            admin.approved_by = current_user.id
            
            # Assign selected roles
            selected_roles = request.form.getlist('roles')
            for role_name in selected_roles:
                role = Role.query.filter_by(name=role_name).first()
                if role and role not in admin.roles:
                    admin.roles.append(role)
            
            flash(f'Admin {admin.email} approved', 'success')
            
        elif action == 'reject':
            db.session.delete(admin)
            flash(f'Admin request rejected', 'warning')
        
        db.session.commit()
    
    pending_admins = User.query.filter_by(status='pending').all()
    all_roles = Role.query.all()
    return render_template('admin_approvals.html', 
                         pending_admins=pending_admins,
                         roles=all_roles)


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    form = AdminLoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            # Check if user has 'admin' or 'super_admin' role and is approved
            if (user.has_role('admin') or user.has_role('super_admin')) and user.status == 'approved':
                login_user(user)
                next_page = request.args.get('next') or url_for('admin_dashboard')
                return redirect(next_page)
            else:
                flash('Account not approved or not an admin', 'warning')
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('admin_login.html', form=form)

GALLERY_FOLDER = os.path.join(app.root_path, 'static', 'gallery')
os.makedirs(GALLERY_FOLDER, exist_ok=True)

@app.route('/admin/gallery', methods=['GET', 'POST'])
@login_required  # or your admin_required decorator
@csrf.exempt
def admin_gallery():
    if request.method == 'POST':
        files = request.files.getlist('image')
        uploaded = 0
        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                save_path = os.path.join(GALLERY_FOLDER, filename)
                # Ensure unique filename
                if os.path.exists(save_path):
                    import uuid
                    filename = f"{uuid.uuid4().hex}_{filename}"
                    save_path = os.path.join(GALLERY_FOLDER, filename)
                file.save(save_path)
                img = GalleryImage(filename=filename)
                db.session.add(img)
                uploaded += 1
        if uploaded:
            db.session.commit()
            flash(f'{uploaded} image(s) uploaded!', 'success')
        else:
            flash('No valid images uploaded.', 'danger')
        return redirect(url_for('admin_gallery'))
    images = GalleryImage.query.order_by(GalleryImage.uploaded_at.desc()).all()
    return render_template('admin_gallery.html', images=images)



@app.route('/admin/gallery/delete/<int:image_id>', methods=['POST'])
@login_required  # or your admin_required decorator
def delete_gallery_image(image_id):
    img = GalleryImage.query.get_or_404(image_id)
    # Delete the image file from the filesystem
    img_path = os.path.join(app.root_path, 'static', 'gallery', img.filename)
    if os.path.exists(img_path):
        os.remove(img_path)
    # Delete from database
    db.session.delete(img)
    db.session.commit()
    flash('Image deleted!', 'success')
    return redirect(url_for('admin_gallery'))

@app.route('/admin/rooms')
@room_management_required
def admin_rooms():
    rooms = Room.query.options(db.joinedload(Room.images)).all()
    return render_template('admin_rooms.html', rooms=rooms)


@app.route('/admin/rooms/create', methods=['GET', 'POST'])
@room_management_required
def create_room():
    form = RoomForm()
    form.room_type.choices = [('single', 'Single'), ('double', 'Double'), ('suite', 'Suite')]
    form.floor.choices = [        ('1', '1st'), 
        ('2', '2nd'), 
        ('3', '3rd')
]
    form.amenities.choices = [('wifi', 'WiFi'), ('ac', 'AC'), ('tv', 'TV'), ('refrigirator', 'REFRIGIRATOR'), 
         ('electric jug', 'ELECTRIC JUG'), 
     
         ('water heater', 'WATER HEATER'),
        ('standard wardrobe', 'STANDARD WARDROBE')]
    # Do NOT render primary_image in the creation template

    if form.validate_on_submit():
        try:
            new_room = Room(
                name=form.name.data,
                description=form.description.data,
                price=form.price.data,
                capacity=form.capacity.data,
                amenities=form.amenities.data,  # Store as JSON array
                status='available',
                cleaning_status = 'clean',
                size= form.size.data,
                bedsize= form.bedsize.data,
                room_type=form.room_type.data,
                floor= form.floor.data
            )
            db.session.add(new_room)
            db.session.flush()  # Get new_room.id before committing
            run_automations('room_created', context={'room': new_room, 'user_id': current_user.id})
            # Handle image uploads
            primary_set = False
            for image in request.files.getlist('images'):
                if image and allowed_file(image.filename):
                    filename = secure_filename(image.filename)
                    unique_filename = f"{uuid.uuid4().hex}_{filename}"
                    image_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                    image.save(image_path)

                    room_image = RoomImage(
                        room_id=new_room.id,
                        filename=unique_filename,
                        is_primary=not primary_set  # First image is primary
                    )
                    if not primary_set:
                        primary_set = True
                    db.session.add(room_image)

            db.session.commit()
            flash('Room created successfully', 'success')
            return redirect(url_for('admin_rooms'))

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Room creation error: {str(e)}")
            flash('Error creating room. Please try again.', 'error')
        
    return render_template('admin_room_create.html', form=form)
        


@app.route('/admin/rooms/deactivate/<int:room_id>', methods=['POST'])
@room_management_required
def deactivate_room(room_id):
    room = Room.query.get_or_404(room_id)
    room.is_active = False
    db.session.commit()
    flash(f'Room "{room.name}" deactivated.', 'success')
    return redirect(url_for('admin_rooms'))

@app.route('/admin/rooms/activate/<int:room_id>', methods=['POST'])
@room_management_required
def activate_room(room_id):
    room = Room.query.get_or_404(room_id)
    room.is_active = True
    db.session.commit()
    flash(f'Room "{room.name}" activated.', 'success')
    return redirect(url_for('admin_rooms'))

    return render_template('admin_room_create.html', form=form)
@app.route('/admin/rooms/edit/<int:room_id>', methods=['GET', 'POST'])
@room_management_required
def edit_room(room_id):
    room = Room.query.get_or_404(room_id)
    form = RoomForm(obj=room)
    
    # Get existing images
    images = RoomImage.query.filter_by(room_id=room.id).order_by(RoomImage.is_primary.desc()).all()
    
    # Initialize form choices
    form.primary_image.choices = [(-1, 'No Primary Image')] + [(img.id, img.filename) for img in images]
    
    if request.method == 'GET':
        primary = next((img.id for img in images if img.is_primary), -1)
        form.primary_image.data = primary
        form.amenities.data = room.amenities  # Directly use the list
    if form.validate_on_submit():
        try:
            # Update basic fields
            room.name = form.name.data
            room.price = float(form.price.data)
            room.capacity = int(form.capacity.data)
            room.size = int(form.size.data)
            room.bedsize = int(form.bedsize.data)
            room.room_type = form.room_type.data
            room.description = form.description.data
            room.amenities = ','.join(form.amenities.data)
            cleaning_status = 'clean'

            # Handle primary image
            if form.primary_image.data != '-1':
                RoomImage.query.filter_by(room_id=room.id).update({'is_primary': False})
                selected_image = RoomImage.query.get(int(form.primary_image.data))
                if selected_image:
                    selected_image.is_primary = True
                    db.session.add(selected_image)

            # Handle new image uploads
            for uploaded_file in form.images.data:
                if uploaded_file and allowed_file(uploaded_file.filename):
                    # Generate unique filename
                    filename = secure_filename(uploaded_file.filename)
                    unique_filename = f"{uuid.uuid4().hex}_{filename}"
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                    
                    # Save file to filesystem
                    uploaded_file.save(filepath)
                    
                    # Create image record
                    new_image = RoomImage(
                        room_id=room.id,
                        filename=unique_filename,
                        is_primary=False
                    )
                    db.session.add(new_image)

            db.session.commit()
            flash('Room updated successfully', 'success')
            return redirect(url_for('admin_rooms'))

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Room update error: {str(e)}")
            flash('Error updating room. Please check the data and try again.', 'error')

    return render_template('admin_room_edit.html',
                         form=form,
                         room=room,
                         images=images)


@app.route('/admin/rooms/delete/<int:room_id>', methods=['POST'])
@room_management_required
def delete_room(room_id):
    try:
        room = Room.query.get_or_404(room_id)
        
        # Check if room has bookings
        if Booking.query.filter_by(room_id=room_id).count() > 0:
            flash('Cannot delete room with active bookings', 'error')
            return redirect(url_for('admin_rooms'))
        
        # Delete associated images
        for image in room.images:
            try:
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], image.filename)
                if os.path.exists(image_path):
                    os.remove(image_path)
            except Exception as file_error:
                app.logger.error(f"Error deleting image file {image.filename}: {str(file_error)}")
            db.session.delete(image)
        
        # Delete the room
        db.session.delete(room)
        db.session.commit()
        room.status = 'deleted'
        db.session.commit()
        flash(f'Room "{room.name}" marked as deleted', 'success')
        flash(f'Room "{room.name}" deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting room {room_id}: {str(e)}")
        flash('Error deleting room. Please try again.', 'error')
    
    return redirect(url_for('admin_rooms'))



@app.route('/confirm_booking', methods=['POST', 'GET'])
@role_required(['receptionist', 'super_admin'])
def confirm_booking():
    otp = request.form.get('otp')
    booking = Booking.query.filter_by(otp=otp).first()
    
    if not booking:
        flash('Invalid OTP', 'error')
        return redirect(url_for('receptionist_dashboard'))
    
    if booking.otp_expiry.replace(tzinfo=None) < datetime.utcnow():
        flash('OTP has expired', 'error')
        return redirect(url_for('receptionist_dashboard'))
    
    booking.check_in_status = 'Confirmed'
    booking.room.status = 'occupied'
    db.session.commit()
    
    flash('Booking confirmed successfully', 'success')
    return redirect(url_for('receptionist_dashboard'))

@app.route('/manual_check_in/<int:booking_id>', methods=['POST'])
@role_required(['receptionist', 'super_admin'])
def manual_check_in(booking_id):
    booking = Booking.query.get_or_404(booking_id)
    booking.check_in_status = 'Checked-in'
    booking.room.status = 'occupied'
    user=db.session.query(User).filter_by(id=booking.user_id).first()
    db.session.commit()
    run_automations('booking_created', context={'booking': booking, 'user_id': user.id})
    flash('Manual check-in successful', 'success')
    return redirect(url_for('receptionist_dashboard'))



@app.route('/receptionist/confirm-booking', methods=['POST'])
@role_required(['receptionist', 'admin'])
def receptionist_confirm_booking():
    otp = request.form.get('otp')
    booking = Booking.query.filter_by(otp=otp).first()
    
    if not booking:
        flash('Invalid OTP', 'error')
        return redirect(url_for('receptionist_dashboard'))
    
    if booking.otp_expiry < datetime.now(NIGERIA_TZ):
        flash('OTP has expired', 'error')
        return redirect(url_for('receptionist_dashboard'))
    
    if booking.check_in_status == 'Confirmed':
        flash('Booking already confirmed', 'warning')
        return redirect(url_for('receptionist_dashboard'))
    
    booking.check_in_status = 'Confirmed'
    booking.room.status = 'occupied'
    db.session.commit()
    
    flash('Booking confirmed successfully', 'success')
    return redirect(url_for('receptionist_dashboard'))

@app.route('/receptionist/check-in/<int:booking_id>', methods=['POST'])
@role_required(['receptionist', 'super_admin'])
def receptionist_manual_check_in(booking_id):
    booking = Booking.query.get_or_404(booking_id)
    
    # ADD PAYMENT VERIFICATION
    if booking.payment_status != 'paid':
        flash('Cannot check-in without successful payment', 'error')
        return redirect(url_for('receptionist_dashboard'))
    
    booking.check_in_status = 'Checked-in'
    booking.room.status = 'occupied'
    db.session.commit()
    
    flash('Manual check-in successful', 'success')
    return redirect(url_for('receptionist_dashboard'))
    flash('Manual check-in successful', 'success')
    return redirect(url_for('receptionist_dashboard'))

from datetime import datetime, timedelta, timezone
@app.route('/receptionist/manual-booking', methods=['GET', 'POST'])
@role_required(['receptionist', 'super_admin'])
def manual_booking():
    form = BookingForm()
    if request.method == 'POST':
        email = request.form.get('email').strip().lower()
        password = request.form.get('password')

        # Check if user exists, else create
        user = User.query.filter_by(email=email).first()
        user_created = False
        if not user:
            # Create user without the role parameter
            user = User(
                username=email.split('@')[0],
                email=email,
                password=generate_password_hash(password),
                status='active',
                created_at=datetime.now(NIGERIA_TZ)
            )
            db.session.add(user)
            db.session.flush()
            
            # Assign user role after creating the user
            user_role = Role.query.filter_by(name='user').first()
            if user_role:
                user.roles.append(user_role)
                
            user_created = True

        # Assign first available room
        room = Room.query.filter_by(status='available').first()
        if not room:
            flash('No available rooms at the moment.', 'error')
            return render_template('manual_booking.html', form=form)

        # Set booking dates: today and tomorrow
        check_in = datetime.now(NIGERIA_TZ)
        check_out = check_in + timedelta(days=1)
        total_price = room.price

        otp_expiry = datetime.combine(check_in.date(), datetime.max.time()).replace(tzinfo=timezone.utc)

        booking = Booking(
            user_id=user.id,
            room_id=room.id,
            check_in_date=check_in,
            check_out_date=check_out,
            total_amount=total_price,
            payment_status='paid',
            check_in_status='Checked-in',
            otp=generate_otp(),
            otp_expiry=otp_expiry
        )
        db.session.add(booking)
        room.status = 'occupied'
        
        # ====== CRITICAL FIX: CREATE PAYMENT RECORD ======
        payment = Payment(
            booking_id=booking.id,
            amount=total_price,
            payment_method='Manual (Reception)',
            created_at=datetime.now(NIGERIA_TZ)
        )
        db.session.add(payment)
        # ================================================
        
        db.session.commit()

        # Send welcome email if user was just created
        if user_created:
            try:
                send_email(
                    to_email=email,
                    subject="Welcome to Our Hotel",
                    body=f"Dear {user.username},\n\nYour account has been created. You can now log in with your email and password.\n\nThank you for choosing us!"
                )
            except Exception as e:
                app.logger.error(f"Error sending welcome email: {e}")

        # Send booking details email
        try:
            send_email(
                to_email=email,
                subject="Your Booking Details",
                body=f"""Dear {user.username},

Your booking is confirmed!

Room: {room.name}
Check-in: {check_in.strftime('%Y-%m-%d')}
Check-out: {check_out.strftime('%Y-%m-%d')}
Total Amount: ₦{total_price:,.2f}
OTP for check-in: {booking.otp} (expires {booking.otp_expiry.strftime('%Y-%m-%d %H:%M')} UTC)

Please present this OTP at the reception for check-in.

Thank you for booking with us!
"""
            )
        except Exception as e:
            app.logger.error(f"Error sending booking details email: {e}")

        flash('Manual booking created successfully! Guest can now log in using their email and password.', 'success')
        return redirect(url_for('receptionist_dashboard'))

    return render_template('manual_booking.html', form=form)

@app.route('/manage_cancellations')
@role_required(['receptionist', 'super_admin'])
def manage_cancellations():
    cancellation_requests = Booking.query.filter(
        Booking.cancellation_status == 'requested'
    ).order_by(Booking.cancellation_requested_at.asc()).all()
    
    return render_template('manage_cancellations.html', requests=cancellation_requests)


@app.route('/handle_cancellation/<int:booking_id>/<action>', methods=['POST'])
@role_required(['receptionist', 'super_admin'])
def handle_cancellation(booking_id, action):
    booking = Booking.query.get_or_404(booking_id)
    if action == 'approve':
        refund_success = True
        if hasattr(booking, 'payment_method') and booking.payment_method == 'Paystack':
            refund_success = process_refund(booking, percent=0.7)
            if not refund_success:
                flash('Refund failed', 'error')
                return redirect(url_for('manage_cancellations'))
        booking.cancellation_status = 'approved'
        booking.room.status = 'available'
        booking.payment_status = 'Refunded'
        flash('Cancellation approved and 70% refund processed', 'success')
        send_email(
            to_email=booking.user.email,
            subject="Booking Cancellation Approved",
            body=f"Your booking #{booking.id} has been cancelled. 70% refund processed."
        )
    elif action == 'deny':
        booking.cancellation_status = 'denied'
        flash('Cancellation denied', 'warning')
        send_email(
            to_email=booking.user.email,
            subject="Cancellation Request Denied",
            body=f"Your cancellation request for booking #{booking.id} was denied."
        )
    db.session.commit()
    return redirect(url_for('manage_cancellations'))

def process_refund(booking):
    if (booking.payment_method == 'Paystack'):
        url = f"{app.config['PAYSTACK_BASE_URL']}/refund"
        headers = {
            "Authorization": f"Bearer {app.config['PAYSTACK_SECRET_KEY']}",
            "Content-Type": "application/json"
        }
        payload = {
            "transaction": booking.payment_reference,
            "amount": int(booking.total_amount * 100)
        }
        
        try:
            response = requests.post(url, headers=headers, json=payload)
            if response.json().get('status'):
                return True
        except Exception as e:
            app.logger.error(f"Refund failed: {e}")
    
    return False

#checkout
# Send checkout OTP 10 minutes before checkout
def send_checkout_reminders():
    with app.app_context():
        now = datetime.now(NIGERIA_TZ)
        reminder_time = now + timedelta(minutes=10)
        
        # Find bookings ending in 10 minutes
        upcoming_checkouts = Booking.query.filter(
            Booking.check_out_date <= reminder_time,
            Booking.check_out_date > now,
            Booking.checkout_otp == None,  # Not sent yet
            Booking.check_in_status == 'Checked-in'
        ).all()
        
        for booking in upcoming_checkouts:
            # Generate OTP
            otp = generate_otp()
            booking.checkout_otp = otp
            booking.checkout_otp_expiry = booking.check_out_date + timedelta(hours=1)
            
            # Send email
            send_email(
                to_email=booking.user.email,
                subject="Checkout Reminder - Hotel Marlin",
                body=f"""Your checkout time is approaching!
                
Checkout OTP: {otp}
Valid until: {booking.checkout_otp_expiry.strftime('%Y-%m-%d %H:%M')}
                
Please use this OTP to check out at the reception. you are to present this otp to the receptionist
                
We hope you enjoyed your stay!"""
            )
            
        db.session.commit()

# Add to scheduler
scheduler.add_job(send_checkout_reminders, 'interval', minutes=1)
from apscheduler.schedulers.background import BackgroundScheduler


# Initialize scheduler
scheduler =  BackgroundScheduler()
scheduler.start()

def send_auto_checkout_email(user):
    msg = Message("Automatic Checkout Completed",
                  sender="hotel@example.com",
                  recipients=[user.email])
    
    msg.html = f"""<html>
<body>
<p>Dear {user.username},</p>
<p>Your checkout at Marlin Hotel has been automatically processed.</p>
<p>We hope you enjoyed your stay! Please consider rating your experience:</p>
<p><a href="{url_for('rate_stay', _external=True)}">Rate Your Stay</a></p>
<p>Sincerely,<br>
The Marlin Hotel Team</p>
</body>
</html>
"""
    mail.send(msg)

@scheduler.scheduled_job('interval', minutes=1)
def check_checkout_times():
    with app.app_context():
        # Check for bookings that need OTP sent
        ten_minutes_from_now = datetime.now(NIGERIA_TZ) + timedelta(minutes=10)
        upcoming_checkouts = Booking.query.filter(
            Booking.check_out_date <= ten_minutes_from_now,
            Booking.check_in_status == 'Checked-in',
            Booking.checkout_otp.is_(None),
            Booking.auto_checked_out == False
        ).all()
        
        for booking in upcoming_checkouts:
            # Generate and send OTP
            otp = booking.generate_checkout_otp()
            send_checkout_otp_email(booking.user, otp)
            db.session.commit()
        
        # Check for overdue checkouts
        now = datetime.now(NIGERIA_TZ)
        overdue_checkouts = Booking.query.filter(
            Booking.check_out_date <= now,
            Booking.check_in_status == 'Checked-in',
            Booking.auto_checked_out == False
        ).all()
        
        for booking in overdue_checkouts:
            # Automatically check out
            booking.check_in_status = 'Checked-out'
            booking.room.status = 'available'
            booking.auto_checked_out = True
            db.session.commit()
            
            # Send auto checkout email
            send_auto_checkout_email(booking.user)

def send_checkout_otp_email(user, otp):
    msg = Message("Your Checkout OTP",
                  sender="hotel@example.com",
                  recipients=[user.email])
    
    msg.html = f"""<html>
<body>
<p>Dear {user.username},</p>
<p>Your checkout OTP is: <strong>{otp}</strong></p>
<p>Please present this code to the receptionist within 30 minutes to complete your checkout.</p>
<p>If you don't check out manually, the system will automatically check you out at your scheduled time.</p>
<p>Sincerely,<br>
The Marlin Hotel Team</p>
</body>
</html>
"""
    mail.send(msg)

@app.route('/checkout/<int:booking_id>', methods=['POST'])
@login_required
@role_required(['receptionist', 'super_admin'])
def checkout(booking_id):
    booking = Booking.query.get_or_404(booking_id)
    otp = request.form.get('otp')
    room= Room.query.get_or_404(Room.id)
    # When a guest checks out
    room = booking.room
    room.status = 'available'
    room.cleaning_status = 'dirty'  # Mark as dirty
    room.last_occupied = date.today()
    db.session.commit()
    # Verify OTP
    if booking.is_otp_valid() and otp == booking.checkout_otp:
        # Complete checkout
        
        booking.check_in_status = 'Checked-out'
        booking.checked_out_at = datetime.now(NIGERIA_TZ)
        booking.room.status = 'available'
        db.session.commit()
        
        # Send thank you email
        send_thank_you_email(booking.user)
        
        flash('Checkout successful!', 'success')
    else:
        flash('Invalid or expired OTP', 'danger')
    
    return redirect(url_for('receptionist_dashboard'))
    

def send_thank_you_email(user):
    msg = Message("Thank You for Staying With Us!",
                  sender="hotel@example.com",
                  recipients=[user.email])
    
    msg.html = f"""<html>
<body>
<p>Dear {user.username},</p>
<p>Thank you for staying at Marlin Hotel! We hope you enjoyed your stay.</p>
<p>We would appreciate it if you could take a moment to rate your experience:</p>
<p><a href="{url_for('rate_stay', _external=True)}">Rate Your Stay</a></p>
<p>Your feedback helps us improve our services.</p>
<p>Sincerely,<br>
The Marlin Hotel Team</p>
</body>
</html>
"""
    mail.send(msg)

# After other scheduler jobs
scheduler.add_job(id='check_booking_expiry',
    func=send_checkout_reminders,
    trigger="interval",
    minutes=1
)

@app.route('/export_bookings_csv')
@login_required
def export_bookings_csv():
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['Guest', 'Room', 'Check-in', 'Check-out', 'Status'])
    for booking in Booking.query.all():
        cw.writerow([
            booking.user.username,
            booking.room.name,
            booking.check_in_date,
            booking.check_out_date,
            booking.check_in_status
        ])
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=bookings.csv"
    output.headers["Content-type"] = "text/csv"
    return output


@app.route('/export_shift_csv')
@login_required
def export_sjifts_csv():
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['staff member', 'position', 'shift type', 'shift date', 'start time',  'end time'])
    for shift in Shift.query.all():
        cw.writerow([
            shift.staff.first_name + "  " + shift.staff.last_name,
            shift.position,
            shift.shift_type,
            shift.shift_date.strftime('%Y-%m-%d'),
            shift.start_time.strftime('%H:%M'),
            shift.end_time.strftime('%H:%M')

        ])
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=bookings.csv"
    output.headers["Content-type"] = "text/csv"
    return output



@app.route('/export_bookings_csv')
@login_required
def export_guests_csv():
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['Guest', 'Room', 'Check-in', 'Check-out', 'Status'])
    guests_query = User.query.filter(User.bookings.any())
    for guest in guests_query.query.all():
        cw.writerow([
            guest.user.username,
            guest.room.name,
            guest.check_in_date,
            guest.check_out_date,
            guest.check_in_status
        ])
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=bookings.csv"
    output.headers["Content-type"] = "text/csv"
    return output


@app.route('/export_payments_csv')
@login_required
def export_payments_csv():
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['payment id', 'amount', 'reference', 'payment Method', 'created at',  'payment date'])
    payments_query = Payment.query.join(Booking).join(User).order_by(desc(Payment.created_at))
    for payment in payments_query.all():
        cw.writerow([
            payment.booking_id,
            payment.amount,
            payment.reference,
            payment.payment_method,
            payment.created_at,
            payment.payment_date
        ])
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=payments.csv"
    output.headers["Content-type"] = "text/csv"
    return output



from models import Payment, Booking, User
from sqlalchemy import desc

@app.route('/receptionist/guests')
@login_required
def guest_list():
    # Get filter parameters
    search_query = request.args.get('search', '')
    status_filter = request.args.get('status', 'all')
    
    # Base query
    guests_query = User.query.filter(User.bookings.any())
    guest_active = Booking.query.filter(User.bookings.any())
    # Apply filters
    if search_query:
        guests_query = guests_query.filter(
            User.username.ilike(f'%{search_query}%') | 
            User.email.ilike(f'%{search_query}%')
        )
    
    if status_filter != 'all':
        guests_query = guests_query.filter(User.status == status_filter)
    
    guests = guests_query.order_by(desc(User.last_login)).all()
    
    return render_template('receptionist/guests.html', 
                          guests=guests,
                          search_query=search_query,
                          status_filter=status_filter, guest_active=guest_active)

@app.route('/receptionist/payments')
@login_required
def payment_list():
    # Get filter parameters
    status_filter = request.args.get('status', 'all')
    date_filter = request.args.get('date', None)
   
    
    # Base query
    payments_query = Payment.query.join(Booking).join(User).order_by(desc(Payment.created_at))
    
    # Apply filters
    if status_filter != 'all':
        payments_query = payments_query.filter(Payment.status == status_filter)
    
    if date_filter:
        payments_query = payments_query.filter(Payment.created_at >= date_filter)
    
    payments = payments_query.all()
    
    return render_template('receptionist/payments.html', 
                          payments=payments,
                          status_filter=status_filter,
                          date_filter=date_filter)



from sqlalchemy import or_, and_, func
@app.route('/receptionist/dashboard')
@login_required
def receptionist_dashboard():
    # Ensure user is receptionist or admin
    if not any(role.name in ['super_admin', 'receptionist'] for role in current_user.roles):
        flash('Access denied.', 'danger')
        return redirect(url_for('home'))
    
    #booking
    booking= Booking.query.all()
    # Date calculations
    today = datetime.now(NIGERIA_TZ).date()
    
    # Get all rooms excluding maintenance
    all_rooms = Room.query.filter(Room.status != 'maintenance').all()
    total_rooms = len(all_rooms)
    
    # Calculate occupied rooms based on active bookings
    occupied_rooms = Room.query.filter_by(status='occupied').count()
    
    # Calculate occupancy rate
    occupancy_rate = 0
    if total_rooms > 0:
        occupancy_rate = (occupied_rooms / total_rooms) * 100
    
    # Today's revenue
    daily_revenue = db.session.query(func.sum(Payment.amount)).filter(
        func.date(Payment.created_at) == today
    ).scalar() or 0

    
    daily_revenue_paid = db.session.query(func.sum(Payment.amount)).filter(
    func.date(Payment.created_at) == today,
    Payment.status == 'success'  # Only successful payments
).scalar() or 0

    payments_today_paid = Payment.query.filter(
    func.date(Payment.created_at) == today,
    Payment.status == 'success'  # Only successful payments
).count()
    # Payments today count
    payments_today = Payment.query.filter(
        func.date(Payment.created_at) == today
    ).count()
    
     # Today's Bookings (ONLY PAID)
    todays_bookings = Booking.query.filter(
        func.date(Booking.check_in_date) == today,
        Booking.payment_status == 'paid'  # ADD THIS FILTER
    ).order_by(Booking.check_in_date.asc()).all()

    # Today's check-ins (ONLY PAID)
    todays_checkins = Booking.query.filter(
        func.date(Booking.check_in_date) == today,
        Booking.payment_status == 'paid',  # ADD THIS FILTER
        Booking.check_in_status == 'Checked-in'
    ).all()
    
    # Count completed check-ins/check-outs
    checked_in_today = Booking.query.filter(
        func.date(Booking.check_in_date) == today,
        Booking.check_in_status == 'Checked-in'
    ).count()
    
    checked_out_today = Booking.query.filter(
        func.date(Booking.check_out_date) == today,
        Booking.check_in_status == 'Checked-out'
    ).count()
    
    # Available rooms
    available_rooms = [room for room in all_rooms if room.status == 'available']
    
    # Calculate next available time for each room
    for room in all_rooms:
        if room.status == 'occupied':
            next_available = Booking.query.filter(
                Booking.room_id == room.id,
                Booking.check_out_date > datetime.now(NIGERIA_TZ)
            ).order_by(Booking.check_out_date.asc()).first()
            room.next_available = next_available.check_out_date if next_available else None
        else:
            room.next_available = None

    # Find next available room (earliest checkout)
    next_available_booking = Booking.query.filter(
        Booking.check_out_date > datetime.now(NIGERIA_TZ)
    ).order_by(Booking.check_out_date.asc()).first()
    next_available_room = next_available_booking.room if next_available_booking else None
    next_available_time = next_available_booking.check_out_date if next_available_booking else None
    
    # Pending cancellations
    pending_cancellations = Booking.query.filter_by(cancellation_status='requested').all()
    
    # Overdue check-outs
    overdue_checkouts = Booking.query.filter(
        Booking.check_out_date < datetime.now(NIGERIA_TZ),
        Booking.check_in_status != 'Checked-out'
    ).all()
    
    # Pending payments
    pending_payments = Booking.query.filter_by(payment_status='pending').all()
    
    # Revenue chart data (last 7 days)
    revenue_labels = []
    revenue_data = []
    for i in range(6, -1, -1):
        day = today - timedelta(days=i)
        revenue_labels.append(day.strftime('%a'))
        revenue = db.session.query(func.sum(Payment.amount)).filter(
            func.date(Payment.created_at) == day
        ).scalar() or 0
        revenue_data.append(revenue)
    
    # Get future bookings (from tomorrow onward)
    future_bookings = Booking.query.filter(
        Booking.check_in_date > today + timedelta(days=1)
    ).order_by(Booking.check_in_date.asc()).all()
    

    
    # Get today's date
    today = datetime.now(NIGERIA_TZ).date()
    
    # Get active check-ins
    active_bookings = Booking.query.filter(
        Booking.check_in_status == 'Checked-in',
        Booking.checked_out == False
    ).options(
        db.joinedload(Booking.room),
        db.joinedload(Booking.user)
    ).all()
    
    # Get upcoming check-outs (today)
    upcoming_checkouts = Booking.query.filter(
        Booking.check_out_date == today,
        Booking.checked_out == False,
        Booking.check_in_status == 'Checked-in'
    ).options(
        db.joinedload(Booking.room),
        db.joinedload(Booking.user)
    ).all()

    return render_template(
        'receptionist_dashboard.html',
        total_rooms=total_rooms,
        occupied_rooms=occupied_rooms,
        occupancy_rate=occupancy_rate,
        daily_revenue=daily_revenue,
        payments_today=payments_today,
        todays_bookings=todays_bookings,
        todays_checkins=todays_checkins,
        checked_in_today=checked_in_today,
        checked_out_today=checked_out_today,
        available_rooms=available_rooms,
        next_available_room=next_available_room,
        next_available_time=next_available_time,
        pending_cancellations=pending_cancellations,
        overdue_checkouts=overdue_checkouts,
        pending_payments=pending_payments,
        revenue_labels=revenue_labels,
        revenue_data=revenue_data,
        all_rooms=all_rooms,
        future_bookings=future_bookings, booking=booking, daily_revenue_paid=daily_revenue_paid,
    payments_today_paid=payments_today_paid, active_bookings=active_bookings,
        upcoming_checkouts=upcoming_checkouts
    )

# Update your hr_dashboard route to include more stats
@app.route('/hr/dashboard')
@role_required(['super_admin', 'hr'])
def hr_dashboard():
    # Calculate stats
    total_staff = Staff.query.count()
    active_staff = Staff.query.filter_by(is_active=True).count()
    inactive_staff = total_staff - active_staff
    all_staff = Staff.query.all()
    # Upcoming shifts stats
    today = datetime.now(NIGERIA_TZ).date()
    upcoming_shifts_count = Shift.query.filter(Shift.shift_date >= today).count()
    tomorrow = today + timedelta(days=1)
    tomorrow_shifts = Shift.query.filter(Shift.shift_date == tomorrow).count()
    attendance_today = Attendance.query.filter(
        Attendance.date == today
    ).options(
        db.joinedload(Attendance.staff)  # Add this joinedload
    ).all()
    
    # Pending admin approvals
    pending_admins = User.query.filter_by(status='pending').count()
    
    # Recent attendance (last 10 records)
    recent_attendance = Attendance.query.order_by(Attendance.date.desc()).limit(10).all()
    
    # Staff distribution by position
    position_counts = db.session.query(
        Staff.position, 
        func.count(Staff.id).label('count')
    ).group_by(Staff.position).all()
    
    positions = [p[0] for p in position_counts]
    position_counts = [p[1] for p in position_counts]
    
    # Shift type distribution
    shift_counts = db.session.query(
        Shift.shift_type, 
        func.count(Shift.id).label('count')
    ).group_by(Shift.shift_type).all()
    
    shift_types = [s[0] for s in shift_counts]
    shift_counts = [s[1] for s in shift_counts]
    
    # Get current UTC time
    current_utc = datetime.now(NIGERIA_TZ)
    
    # Get shifts for the next 7 days
    start_date = current_utc.date()
    end_date = start_date + timedelta(days=7)
    
    shifts = Shift.query.filter(
        Shift.shift_date >= start_date,
        Shift.shift_date <= end_date
    ).order_by(Shift.shift_date.asc(), Shift.start_time.asc()).all()
    
    # Process shifts - convert to UTC and determine status
    for shift in shifts:
        # Convert start_time to UTC if naive
        if shift.start_time.tzinfo is None:
            shift.start_time_utc = shift.start_time.replace(tzinfo=timezone.utc)
        else:
            shift.start_time_utc = shift.start_time.astimezone(timezone.utc)
            
        # Convert end_time to UTC if naive
        if shift.end_time.tzinfo is None:
            shift.end_time_utc = shift.end_time.replace(tzinfo=timezone.utc)
        else:
            shift.end_time_utc = shift.end_time.astimezone(timezone.utc)
            
        # Calculate status
        if shift.start_time_utc <= current_utc <= shift.end_time_utc:
            shift.status = "Active"
        elif shift.start_time_utc > current_utc:
            shift.status = "Upcoming"
        else:
            shift.status = "Completed"
    
    return render_template(
        'hr/dashboard.html',
        total_staff=total_staff,
        active_staff=active_staff,
        inactive_staff=inactive_staff,
        upcoming_shifts=upcoming_shifts_count,
        tomorrow_shifts=tomorrow_shifts,
        pending_admins=pending_admins,
        recent_attendance=recent_attendance,
        positions=positions,
        position_counts=position_counts,
        shift_types=shift_types,
        shift_counts=shift_counts,
        shifts=shifts,
        current_utc=current_utc,
        current_local=datetime.now().astimezone(),     attendance_today=attendance_today,all_staff=all_staff,
    )


@app.route('/hr/attendance')
@hr_required
def hr_attendance():
    # Get filter parameters
    staff_id = request.args.get('staff_id', type=int)
    date_filter = request.args.get('date_filter', 'all')
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')
    status_filter = request.args.get('status', 'all')
    
    # Base query
    query = Attendance.query.join(Staff)
    
    # Staff filter
    if staff_id:
        query = query.filter(Attendance.staff_id == staff_id)
    
    # Status filter
    if status_filter != 'all':
        query = query.filter(Attendance.status == status_filter)
    
    # Date range filter
    now = datetime.now(NIGERIA_TZ)
    if date_filter == 'today':
        query = query.filter(Attendance.date == now.date())
    elif date_filter == 'week':
        start_of_week = now - timedelta(days=now.weekday())
        query = query.filter(Attendance.date >= start_of_week.date())
    elif date_filter == 'month':
        query = query.filter(
            extract('month', Attendance.date) == now.month,
            extract('year', Attendance.date) == now.year
        )
    elif date_filter == 'custom' and start_date_str and end_date_str:
        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
            query = query.filter(Attendance.date.between(start_date, end_date))
        except ValueError:
            flash('Invalid date format. Use YYYY-MM-DD', 'error')
    
    # Pagination
    page = request.args.get('page', 1, type=int)
    attendances = query.order_by(Attendance.date.desc(), Attendance.clock_in_time.desc()).paginate(
        page=page, per_page=25, error_out=False
    )
    
    # Staff list for dropdown
    staff_members = Staff.query.order_by(Staff.first_name).all()
    
    return render_template('hr_attendance.html',
        attendances=attendances,
        staff_members=staff_members,
        filters={
            'staff_id': staff_id,
            'date_filter': date_filter,
            'start_date': start_date_str,
            'end_date': end_date_str,
            'status': status_filter
        },
        status_options=['all', 'on-time', 'late', 'absent', 'early-departure', 'completed']
    )


# HR Staff Management Hub
@app.route('/hr/staff')
@login_required
@hr_required
def hr_staff_management():
    # Use joinedload to fetch related user in the same query
    staff_members = Staff.query.options(joinedload(Staff.user)).all()
    return render_template('hr/staff.html', staff_members=staff_members)

# HR Shift Management Hub

@app.route('/hr/shifts')
@role_required(['super_admin', 'hr'])
def hr_shift_management():
    # Get filter parameters
    position_filter = request.args.get('position', '')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    # Build query
    query = Shift.query.options(db.joinedload(Shift.staff))
    
    if position_filter:
        query = query.filter(Shift.position == position_filter)
    
    if start_date:
        start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
        query = query.filter(Shift.shift_date >= start_date)
    
    if end_date:
        end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
        query = query.filter(Shift.shift_date <= end_date)

    # Get current UTC time
    current_utc = datetime.now(NIGERIA_TZ)
    
    # Get timezone for conversion
    local_tz = datetime.now().astimezone().tzinfo
    
    # Get shifts and process times
    shifts = query.order_by(Shift.shift_date.asc(), Shift.start_time.asc()).all()
    
    for shift in shifts:
        # Convert start_time to UTC if naive
        if shift.start_time.tzinfo is None:
            shift.start_time_utc = shift.start_time.replace(tzinfo=timezone.utc)
        else:
            shift.start_time_utc = shift.start_time.astimezone(timezone.utc)
            
        # Convert end_time to UTC if naive
        if shift.end_time.tzinfo is None:
            shift.end_time_utc = shift.end_time.replace(tzinfo=timezone.utc)
        else:
            shift.end_time_utc = shift.end_time.astimezone(timezone.utc)
            
        # Calculate status
        if shift.start_time_utc <= current_utc <= shift.end_time_utc:
            shift.status = "Active"
        elif shift.start_time_utc > current_utc:
            shift.status = "Upcoming"
        else:
            shift.status = "Completed"
        
        # Convert to local time for display
        shift.start_local = shift.start_time_utc.astimezone(local_tz)
        shift.end_local = shift.end_time_utc.astimezone(local_tz)

    # Get unique positions for filter dropdown
    positions = db.session.query(Shift.position).distinct().all()
    positions = [p[0] for p in positions if p[0]]

    return render_template('hr/shifts.html',
        shifts=shifts,
        positions=positions,
        current_utc=current_utc,
        current_local=datetime.now().astimezone()
    )


   



# HR Admin Management Hub
from sqlalchemy.orm import joinedload
# In your app.py
@app.route('/hr/admins')
@login_required
@hr_required  # Make sure to add this decorator
def hr_admin_management():
    # Fetch both approved and pending admins
    pending_admins = User.query.join(User.roles)\
        .filter(Role.name == 'admin', User.status == 'pending')\
        .options(joinedload(User.roles))\
        .all()
    
    approved_admins = User.query.join(User.roles)\
        .filter(Role.name == 'admin', User.status == 'approved')\
        .options(joinedload(User.approved_by_user))\
        .all()
    
    
    return render_template('hr/admin.html',
                          pending_admins=pending_admins,
                          approved_admins=approved_admins)



                          
# Deactivate staff route
@app.route('/staff/deactivate/<int:staff_id>', methods=['POST'])
@role_required(['super_admin'])
def deactivate_staff(staff_id):
    staff = Staff.query.get_or_404(staff_id)
    staff.is_active = False  # Deactivate instead of delete
    db.session.commit()
    flash('Staff account deactivated successfully', 'success')
    return redirect(url_for('staff_list'))

from datetime import timedelta

@app.context_processor
def inject_timedelta():
    return dict(timedelta=timedelta)

# activate staff route
@app.route('/staff/activate/<int:staff_id>', methods=['POST'])
@role_required(['super_admin'])
def activate_staff(staff_id):
    staff = Staff.query.get_or_404(staff_id)
    staff.is_active = True  # Reactivate staff
    db.session.commit()
    flash('Staff account activated successfully', 'success')
    return redirect(url_for('staff_list'))

# HR Generate Admin Token
@app.route('/hr/generate-admin-token', methods=['POST'])
@hr_required
def hr_generate_admin_token():
    try:
        # Clear existing tokens
        AdminRegistrationToken.query.delete()
        
        # Create new token
        new_token = AdminRegistrationToken( 
            token=secrets.token_urlsafe(32),
            generated_by=current_user.id,
            expires_at=datetime.now(NIGERIA_TZ) + timedelta(hours=24)
        )

        db.session.add(new_token)
        db.session.commit()
        
        flash('New admin registration token generated!', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Token generation error: {str(e)}")
        flash('Failed to generate token', 'error')
    
    return redirect(url_for('hr_admin_management'))

# HR Approve Admin

@app.route('/hr/approve-admin/<int:admin_id>', methods=['POST'])
@hr_required
def hr_approve_admin(admin_id):
    try:
        admin = User.query.get_or_404(admin_id)
        selected_roles = request.form.getlist('roles')
        
        if not selected_roles:
            flash('At least one role must be selected', 'error')
            return redirect(url_for('hr_admin_management'))
        
        # Clear existing roles and assign new ones
        admin.roles = []
        for role_name in selected_roles:
            role = Role.query.filter_by(name=role_name).first()
            if role:
                admin.roles.append(role)
        
        admin.status = 'approved'
        admin.approved_at = datetime.now(NIGERIA_TZ)
        admin.approved_by = current_user.id
        
        db.session.commit()
        
        # Send notification email
        send_email(
            to_email=admin.email,
            subject="Admin Account Approved",
            body=f"Your admin account has been approved with roles: {', '.join(selected_roles)}."
        )
        
        flash(f'{admin.email} approved with roles: {", ".join(selected_roles)}', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Admin approval error: {str(e)}")
        flash(f'Approval failed: {str(e)}', 'error')
    
    return redirect(url_for('hr_admin_management'))

# HR Reject Admin
@app.route('/hr/reject-admin/<int:admin_id>', methods=['POST'])
@hr_required
def hr_reject_admin(admin_id):
    admin = User.query.get_or_404(admin_id)
    try:
        db.session.delete(admin)
        db.session.commit()
        flash('Admin request rejected', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error rejecting admin: {str(e)}', 'error')
    return redirect(url_for('hr_admin_management'))

# Add these imports at the top if not already present
from sqlalchemy import desc

# ... existing code ...

@app.route('/housekeeping/rooms')
@housekeeping_required

def housekeeping_rooms():
    """Show rooms needing cleaning"""
    # Get rooms that need cleaning
    rooms = Room.query.filter(
        Room.cleaning_status.in_(['dirty', 'needs_attention'])
    ).order_by(Room.last_cleaned.asc()).all()
    
    return render_template('housekeeping_rooms.html', 
                         rooms=rooms,
                         title='Rooms Needing Cleaning')


@app.route('/housekeeping/mark_cleaned/<int:room_id>', methods=['POST'])
@role_required(['housekeeping_supervisor', 'super_admin'])
def mark_room_cleaned(room_id):
    room = Room.query.get_or_404(room_id)
    
    if room.cleaning_status == 'dirty':
        room.cleaning_status = 'clean'
        room.last_cleaned = datetime.now(NIGERIA_TZ)
        db.session.commit()
        
        # Create log entry
        log = CleaningLog(
            room_id=room.id,
            start_time=datetime.now(NIGERIA_TZ),
            end_time=datetime.now(NIGERIA_TZ),
            status='completed',
            notes="Manually marked as cleaned by supervisor"
        )
        db.session.add(log)
        db.session.commit()
        
        flash(f'Room {room.name} marked as cleaned!', 'success')
    else:
        flash(f'Room {room.name} is not dirty', 'warning')
    
    return redirect(url_for('housekeeping_rooms'))


@app.route('/housekeeping/progress', methods=['GET','POST'])
@housekeeping_required

def housekeeping_progress():
    """Show in-progress cleaning assignments"""
    # Get active cleaning assignments
    active_assignments = CleaningAssignment.query.filter(
        CleaningAssignment.status.in_(['pending', 'in_progress'])
    ).order_by(CleaningAssignment.due_by.asc()).all()
    
    return render_template('housekeeping_progress.html', 
                         assignments=active_assignments,
                         title='Cleaning In Progress')

@app.route('/housekeeping/issues')
@role_required(['super_admin', 'housekeeping_supervisor'])
def housekeeping_issues():
    """Show rooms needing special attention"""
    # Get rooms needing attention
    problem_rooms = Room.query.filter(
        or_(
            Room.cleaning_status == 'needs_attention',
            Room.last_cleaned < date.today() - timedelta(days=1)
        )
    ).all()
    
    return render_template('housekeeping_issues.html', 
                         rooms=problem_rooms,
                         title='Rooms Needing Attention')

# ... existing housekeeping_dashboard route ...

# Update the housekeeping_dashboard function to include counts
# app.py
@app.route('/housekeeping/dashboard')
@role_required(['housekeeping_supervisor', 'super_admin'])
def housekeeping_dashboard():
    # Room status counts
    status_counts = db.session.query(
        Room.cleaning_status,
        func.count(Room.id)
    ).group_by(Room.cleaning_status).all()
    
    # Convert to dictionary
    room_status = {status: count for status, count in status_counts}
    
    # Get current Nigeria time
    nigeria_tz = pytz.timezone('Africa/Lagos')
    today_ng = datetime.now(nigeria_tz).date()
    
    # Dashboard stats
    in_progress_cleaning = CleaningAssignment.query.filter(
        CleaningAssignment.status == 'in_progress'
    ).count()
    
    cleaned_today = CleaningLog.query.filter(
        func.date(CleaningLog.end_time) == today_ng,
        CleaningLog.status == 'completed'
    ).count()
    
    attention_rooms = Room.query.filter(
        Room.cleaning_status == 'dirty'
    ).count()
    
    active_requests = MaintenanceRequest.query.filter(
        MaintenanceRequest.status == 'Open'
    ).count()
    
     # Active assignments with room and staff information
    active_assignments = CleaningAssignment.query.options(
        db.joinedload(CleaningAssignment.room),
        db.joinedload(CleaningAssignment.staff)
    ).filter(
        CleaningAssignment.status.in_(['pending', 'in_progress'])
    ).order_by(CleaningAssignment.due_by.asc()).limit(5).all()
    
    # Problem rooms (dirty and not assigned)
    problem_rooms = Room.query.filter(
        Room.cleaning_status == 'dirty'
    ).all()
    
    # Recent cleaning logs
    recent_logs = CleaningLog.query.order_by(
        CleaningLog.start_time.desc()
    ).limit(10).all()
    
    return render_template('housekeeping_dashboard.html',
        room_status=room_status,
        needs_cleaning=room_status.get('dirty', 0),
        in_progress_cleaning=in_progress_cleaning,
        cleaned_today=cleaned_today,
        attention_rooms=attention_rooms,
        active_requests=active_requests,
        active_assignments=active_assignments,
        problem_rooms=problem_rooms,
        recent_logs=recent_logs
    )
# Add these routes to app.py

@app.route('/housekeeping/logs')
@housekeeping_required
def housekeeping_logs():
    """Display all cleaning logs"""
    page = request.args.get('page', 1, type=int)
    logs = CleaningLog.query.order_by(CleaningLog.start_time.desc()).paginate(page=page, per_page=10)
    return render_template('housekeeping_logs.html', logs=logs)




@app.route('/housekeeping/schedule')
@housekeeping_required
def housekeeping_schedule():
    today = datetime.now(NIGERIA_TZ).date()
    start_of_week = today - timedelta(days=today.weekday())
    dates = [start_of_week + timedelta(days=i) for i in range(7)]
    
    assignments = {}
    for date in dates:
        assignments[date] = CleaningAssignment.query.filter(
            func.date(CleaningAssignment.due_by) == date
        ).options(
            db.joinedload(CleaningAssignment.room),
            db.joinedload(CleaningAssignment.staff)
        ).all()
    
    return render_template('housekeeping_schedule.html', 
                         dates=dates,
                         assignments=assignments,
                         today=today)


@app.route('/housekeeping/assignments')
@housekeeping_required
def housekeeping_assignments():
    """Display housekeeping assignments"""
    assignments = CleaningAssignment.query.filter(
        CleaningAssignment.status != 'completed'
    ).order_by(CleaningAssignment.priority.asc()).all()
    return render_template('housekeeping_assignments.html', assignments=assignments)

@app.route('/housekeeping/assignment/<int:assignment_id>/complete', methods=['POST'])
@housekeeping_required
def complete_assignment(assignment_id):
    """Mark a cleaning assignment as complete"""
    assignment = CleaningAssignment.query.get_or_404(assignment_id)
    
    # Create cleaning log
    log = CleaningLog(
        assignment_id=assignment.id,
        
        staff_id=assignment.staff_id,
        start_time=assignment.assigned_at,
        end_time=datetime.now(NIGERIA_TZ),
        status='completed',
        notes=request.form.get('notes', '')
    )
    db.session.add(log)
    
    # Update assignment status
    assignment.status = 'completed'
    assignment.completed_at = datetime.now(NIGERIA_TZ)
    
    # Update room status
    assignment.room.last_cleaned = datetime.now(NIGERIA_TZ)
    assignment.room.cleaning_status = 'clean'
    
    db.session.commit()
    flash('Assignment marked as completed', 'success')
    return redirect(url_for('housekeeping_assignments'))





@app.route('/housekeeping/complete/<int:assignment_id>', methods=['POST'])
@role_required(['staff'])
def complete_cleaning_assignment(assignment_id):
    assignment = CleaningAssignment.query.get_or_404(assignment_id)
    
    # Update status
    assignment.status = 'completed'
    assignment.room.cleaning_status = 'clean'
    assignment.room.last_cleaned = datetime.now(NIGERIA_TZ)
    
    # Create log
    log = CleaningLog(
        room_id=assignment.room_id,
        staff_id=assignment.staff_id,
        start_time=datetime.now(NIGERIA_TZ) - timedelta(minutes=30),  # Assume 30 min task
        end_time=datetime.now(NIGERIA_TZ),
        status='completed'
    )
    db.session.add(log)
    db.session.commit()
    
    flash('Cleaning task completed!', 'success')
    return redirect(url_for('housekeeping_assignments'))

def send_rating_request(booking):
    rating_link = url_for('rate_stay', booking_id=booking.id, _external=True)
    quick_rating_link = url_for('rate_stay1', booking_id=booking.id, _external=True)
    
    send_email(
        to_email=booking.user.email,
        subject="How was your stay?",
        body=(
            f"We hope you enjoyed your stay at Hotel Marlin!\n\n"
            f"Please take a moment to rate your experience:\n"
            f"Detailed Rating: {rating_link}\n"
            f"Quick Rating: {quick_rating_link}\n\n"
            f"Your feedback helps us improve our services!"
        )
    )


@app.route('/rate_stay/<int:booking_id>', methods=['GET', 'POST'])
@login_required
def rate_stay(booking_id):
    booking = Booking.query.get_or_404(booking_id)
    
    # Check if user is authorized and booking is completed
    if booking.user_id != current_user.id:
        abort(403)
    
    if booking.payment_status != 'paid' or booking.check_in_status != 'Checked-out':
        flash('You can only rate completed stays', 'error')
        return redirect(url_for('my_bookings'))
    
    # Check if already rated
    if booking.rating:
        flash('You have already rated this stay', 'info')
        return redirect(url_for('my_bookings'))
    
    form = RatingForm()
    
    if form.validate_on_submit():
        rating = Rating(
            booking_id=booking.id,
            rating=form.rating.data,
            comments=form.comments.data
        )
        db.session.add(rating)
        booking.is_rated = True
        db.session.commit()
        
        flash('Thank you for your feedback!', 'success')
        return redirect(url_for('my_bookings'))
    
    return render_template('rate_stay.html', form=form, booking=booking)

@app.route('/rate_stay1/<int:booking_id>', methods=['GET', 'POST'])
@login_required
def rate_stay1(booking_id):
    # Simplified version without comments
    booking = Booking.query.get_or_404(booking_id)
    
    if booking.user_id != current_user.id:
        abort(403)
    
    if booking.payment_status != 'paid' or booking.check_in_status != 'Checked-out':
        flash('You can only rate completed stays', 'error')
        return redirect(url_for('my_bookings'))
    
    if booking.is_rated:
        flash('You have already rated this stay', 'info')
        return redirect(url_for('my_bookings'))
    
    if request.method == 'POST':
        rating_value = request.form.get('rating')
        if not rating_value:
            flash('Please select a rating', 'error')
            return redirect(url_for('rate_stay1', booking_id=booking.id))
        
        rating = Rating(
            booking_id=booking.id,
            rating=int(rating_value),
            comments="Quick rating"
        )
        db.session.add(rating)
        booking.is_rated = True
        db.session.commit()
        
        flash('Rating submitted!', 'success')
        return redirect(url_for('my_bookings'))
    
    return render_template('rate_stay1.html', booking=booking)

# app.py
@app.route('/staff/id_card/<int:staff_id>')
@role_required(['super_admin', 'staff'])
def staff_id_card(staff_id):
    staff = Staff.query.get_or_404(staff_id)
    
    # Verify staff ownership
    if staff.user_id != current_user.id and not current_user.has_role('super_admin'):
        abort(403)
    
    return render_template('staff_id_card.html', staff=staff)


@app.route('/finance/dashboard')
@role_required(['finance_admin', 'super_admin'])
def finance_dashboard():
    from sqlalchemy import func
    from dateutil.relativedelta import relativedelta

    today = datetime.now(NIGERIA_TZ).date()
    start_of_month = today.replace(day=1)

    # Revenue calculations
    booking_revenue = db.session.query(func.sum(Payment.amount)).filter(Payment.status == 'success').scalar() or 0
    bar_orders_revenue = db.session.query(func.sum(BarOrder.total_amount)).filter(BarOrder.payment_status == 'paid').scalar() or 0

    # Total revenue (bookings + bar orders)
    total_revenue = float(booking_revenue) + float(bar_orders_revenue)

    # Daily revenue (today, bookings + bar orders)
    daily_booking_revenue = db.session.query(func.sum(Payment.amount)).filter(
        func.date(Payment.created_at) == today,
        Payment.status == 'success'
    ).scalar() or 0
    daily_bar_orders_revenue = db.session.query(func.sum(BarOrder.total_amount)).filter(
        func.date(BarOrder.created_at) == today,
        BarOrder.payment_status == 'paid'
    ).scalar() or 0
    daily_revenue = float(daily_booking_revenue) + float(daily_bar_orders_revenue)

    # Monthly revenue (bookings + bar orders)
    monthly_booking_revenue = db.session.query(func.sum(Payment.amount)).filter(
        Payment.payment_date >= start_of_month,
        Payment.status == 'success'
    ).scalar() or 0
    monthly_bar_orders_revenue = db.session.query(func.sum(BarOrder.total_amount)).filter(
        BarOrder.created_at >= start_of_month,
        BarOrder.payment_status == 'paid'
    ).scalar() or 0
    monthly_revenue = float(monthly_booking_revenue) + float(monthly_bar_orders_revenue)

    # Expense calculations
    monthly_expenses = db.session.query(func.sum(Expense.amount)).filter(
        Expense.date >= start_of_month
    ).scalar() or 0

    net_profit = float(monthly_revenue) - float(monthly_expenses)

    # Expense by category
    expense_categories = db.session.query(
        Expense.category,
        func.sum(Expense.amount).label('total')
    ).filter(
        Expense.date >= start_of_month
    ).group_by(Expense.category).all()

    categories = [cat[0] for cat in expense_categories]
    amounts = [float(cat[1]) for cat in expense_categories]

    # Revenue trend (last 6 months)
    revenue_data = []
    expense_data = []
    month_labels = []
    for i in range(5, -1, -1):
        month_date = today - relativedelta(months=i)
        month_start = month_date.replace(day=1)
        next_month = month_start + relativedelta(months=1)
        month_end = next_month - timedelta(days=1)

        month_booking_rev = db.session.query(func.sum(Payment.amount)).filter(
            Payment.payment_date >= month_start,
            Payment.payment_date <= month_end,
            Payment.status == 'success'
        ).scalar() or 0
        month_barorder_rev = db.session.query(func.sum(BarOrder.total_amount)).filter(
            BarOrder.created_at >= month_start,
            BarOrder.created_at <= month_end,
            BarOrder.payment_status == 'paid'
        ).scalar() or 0
        month_rev = float(month_booking_rev) + float(month_barorder_rev)

        month_exp = db.session.query(func.sum(Expense.amount)).filter(
            Expense.date >= month_start,
            Expense.date <= month_end
        ).scalar() or 0

        revenue_data.append(float(month_rev))
        expense_data.append(float(month_exp))
        month_labels.append(month_start.strftime('%b %Y'))

    recent_expenses = Expense.query.order_by(Expense.date.desc()).limit(5).all()

    # Revenue breakdown for template
    revenue_breakdown = {
        'Bookings': float(booking_revenue),
        'Bar Orders': float(bar_orders_revenue),
    }

    return render_template('finance_dashboard.html',
        total_revenue=total_revenue,
        daily_revenue=daily_revenue,
        monthly_revenue=monthly_revenue,
        monthly_expenses=monthly_expenses,
        net_profit=net_profit,
        expense_categories=expense_categories,
        categories=categories,
        amounts=amounts,
        revenue_data=revenue_data,
        expense_data=expense_data,
        month_labels=month_labels,
        recent_expenses=recent_expenses,
        revenue_breakdown=revenue_breakdown
    )


# Add Expense
@app.route('/finance/expenses/add', methods=['GET', 'POST'])
@role_required(['finance_admin', 'super_admin'])
def add_expense():
    form = ExpenseForm()
    
    if form.validate_on_submit():
        try:
            # Handle file upload
            filename = None
            if form.document.data:
                file = form.document.data
                if allowed_file(file.filename):
                    filename = secure_filename(f"{uuid.uuid4().hex}_{file.filename}")
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'expenses', filename)
                    os.makedirs(os.path.dirname(file_path), exist_ok=True)
                    file.save(file_path)
            
            expense = Expense(
                date=form.date.data,
                amount=form.amount.data,
                category=form.category.data,
                description=form.description.data,
                vendor=form.vendor.data,
                payment_method=form.payment_method.data,
                recorded_by=current_user.id,
                document_path=filename
            )
            
            db.session.add(expense)
            db.session.commit()
            
            flash('Expense recorded successfully!', 'success')
            return redirect(url_for('view_expenses'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error recording expense: {str(e)}', 'error')
    
    return render_template('add_expense.html', form=form)

# View Expenses
@app.route('/finance/expenses')
@role_required(['finance_admin', 'super_admin'])
def view_expenses():
    page = request.args.get('page', 1, type=int)
    category_filter = request.args.get('category', 'all')
    date_filter = request.args.get('date', '')
    
    query = Expense.query.order_by(Expense.date.desc())
    
    if category_filter != 'all':
        query = query.filter_by(category=category_filter)
    
    if date_filter:
        try:
            filter_date = datetime.strptime(date_filter, '%Y-%m').date()
            start_date = filter_date.replace(day=1)
            end_date = start_date + relativedelta(months=1)
            query = query.filter(Expense.date >= start_date, Expense.date < end_date)
        except ValueError:
            pass
    
    expenses = query.paginate(page=page, per_page=20)
    
    # Get unique categories for filter dropdown
    categories = db.session.query(Expense.category).distinct().all()
    categories = [cat[0] for cat in categories]
    
    return render_template('view_expenses.html', 
                         expenses=expenses,
                         categories=categories,
                         selected_category=category_filter,
                         date_filter=date_filter)

# Financial Reports
@app.route('/finance/reports')
@role_required(['finance_admin', 'super_admin'])
def financial_reports():
    # Generate P&L report
    today = datetime.now(NIGERIA_TZ).date()
    start_of_year = today.replace(month=1, day=1)
    
    # Monthly revenue
    monthly_revenue = []
    monthly_expenses = []
    monthly_profit = []
    month_labels = []
    
    for i in range(1, 13):
        month_start = start_of_year.replace(month=i)
        next_month = month_start + relativedelta(months=1)
        
        # Revenue for month
        rev = db.session.query(func.sum(Payment.amount)).filter(
            Payment.payment_date >= month_start,
            Payment.payment_date < next_month,
            Payment.status == 'success'
        ).scalar() or 0
        
        # Expenses for month
        exp = db.session.query(func.sum(Expense.amount)).filter(
            Expense.date >= month_start,
            Expense.date < next_month
        ).scalar() or 0
        
        monthly_revenue.append(float(rev))
        monthly_expenses.append(float(exp))
        monthly_profit.append(float(rev - exp))
        month_labels.append(month_start.strftime('%b'))
    
    # Expense breakdown
    expense_breakdown = db.session.query(
        Expense.category,
        func.sum(Expense.amount).label('total')
    ).filter(
        Expense.date >= start_of_year
    ).group_by(Expense.category).all()
    
    # Vendor spending
    vendor_spending = db.session.query(
        Expense.vendor,
        func.sum(Expense.amount).label('total')
    ).filter(
        Expense.date >= start_of_year
    ).group_by(Expense.vendor).order_by(func.sum(Expense.amount).desc()).limit(10).all()
    
    return render_template('financial_reports.html',
        monthly_revenue=monthly_revenue,
        monthly_expenses=monthly_expenses,
        monthly_profit=monthly_profit,
        month_labels=month_labels,
        expense_breakdown=expense_breakdown,
        vendor_spending=vendor_spending
    )



# Store Inventory Routes
@app.route('/inventory/dashboard')
@role_required(['super_admin', 'store_keeper'])
def inventory_dashboard():
    # Get inventory statistics
    total_items = StoreInventory.query.count()
    low_stock_items = StoreInventory.query.filter(
        StoreInventory.quantity <= StoreInventory.reorder_level
    ).count()
    pending_requests = InventoryRequest.query.filter_by(status='pending').count()
    
    # Calculate total inventory value
    total_value = db.session.query(
        func.sum(StoreInventory.unit_cost * StoreInventory.quantity)
    ).scalar() or 0
    
    # Get inventory distribution by category
    categories = db.session.query(
        StoreInventory.category,
        func.count(StoreInventory.id).label('count')
    ).group_by(StoreInventory.category).all()
    
    # Get monthly usage data for last 6 months
    six_months_ago = datetime.now() - timedelta(days=180)
    monthly_usage = db.session.query(
        func.extract('month', InventoryUsage.used_at).label('month'),
        func.extract('year', InventoryUsage.used_at).label('year'),
        func.sum(InventoryUsage.quantity_used).label('total_used')
    ).filter(InventoryUsage.used_at >= six_months_ago
    ).group_by('year', 'month').order_by('year', 'month').all()
    
    # Get low stock items
    low_stock = StoreInventory.query.filter(
        StoreInventory.quantity <= StoreInventory.reorder_level
    ).order_by(StoreInventory.quantity.asc()).limit(10).all()
    
    # Get pending requests
    pending = InventoryRequest.query.filter_by(
        status='pending'
    ).order_by(InventoryRequest.requested_at.desc()).limit(5).all()
    
    # Get recent inventory usage
    recent_usage = InventoryUsage.query.options(
        db.joinedload(InventoryUsage.item),
        db.joinedload(InventoryUsage.used_by)
    ).order_by(InventoryUsage.used_at.desc()).limit(10).all()
    
    # Prepare chart data
    category_labels = [c[0] for c in categories]
    category_counts = [c[1] for c in categories]
    
    month_labels = []
    usage_data = []
    for usage in monthly_usage:
        # Create a date object from year and month
        date_str = f"{int(usage.year)}-{int(usage.month)}-01"
        month_date = datetime.strptime(date_str, '%Y-%m-%d')
        # Format as abbreviated month name and year
        month_labels.append(month_date.strftime('%b %Y'))
        usage_data.append(usage.total_used)
    
    return render_template('inventory_dashboard.html',
        total_items=total_items,
        low_stock_items=low_stock_items,
        pending_requests=pending_requests,
        total_value=total_value,
        category_labels=category_labels,
        category_counts=category_counts,
        month_labels=month_labels,
        usage_data=usage_data,
        low_stock=low_stock,
        pending=pending,
        recent_usage=recent_usage
    )
    
@app.route('/inventory')
@role_required(['super_admin', 'store_keeper'])
def inventory_list():
    items = StoreInventory.query.all()
    return render_template('inventory/list.html', items=items)

@app.route('/inventory/add', methods=['GET', 'POST'])
@role_required(['super_admin', 'store_keeper'])
def add_inventory_item():
    form = InventoryForm()
    if form.validate_on_submit():
        try:
            item = StoreInventory(
                name=form.name.data,
                description=form.description.data,
                category=form.category.data,
                unit=form.unit.data,
                quantity=form.quantity.data,
                reorder_level=form.reorder_level.data,
                unit_cost=form.unit_cost.data,
                supplier=form.supplier.data,
                created_by_id=current_user.id,
                updated_by_id=current_user.id
            )
            db.session.add(item)
            db.session.commit()
            flash('Inventory item added successfully!', 'success')
            return redirect(url_for('inventory_list'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding item: {str(e)}', 'error')
    return render_template('inventory/form.html', form=form, title="Add Inventory Item")

@app.route('/inventory/edit/<int:item_id>', methods=['GET', 'POST'])
@role_required(['super_admin', 'store_keeper'])
def edit_inventory_item(item_id):
    item = StoreInventory.query.get_or_404(item_id)
    form = InventoryForm(obj=item)
    if form.validate_on_submit():
        try:
            form.populate_obj(item)
            item.updated_by_id = current_user.id
            db.session.commit()
            flash('Inventory item updated successfully!', 'success')
            return redirect(url_for('inventory_list'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating item: {str(e)}', 'error')
    return render_template('inventory/form.html', form=form, title="Edit Inventory Item")

@app.route('/inventory/delete/<int:item_id>', methods=['POST'])
@role_required(['super_admin', 'store_keeper'])
def delete_inventory_item(item_id):
    item = StoreInventory.query.get_or_404(item_id)
    try:
        db.session.delete(item)
        db.session.commit()
        flash('Inventory item deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting item: {str(e)}', 'error')
    return redirect(url_for('inventory_list'))

@app.route('/inventory/reports')
@role_required(['super_admin', 'store_keeper'])
def inventory_reports():
    # Calculate inventory statistics
    total_items = StoreInventory.query.count()
    total_value = db.session.query(
        func.sum(StoreInventory.quantity * StoreInventory.unit_cost)
    ).scalar() or 0
    
    low_stock_items = StoreInventory.query.filter(
        StoreInventory.quantity <= StoreInventory.reorder_level
    ).count()
    
    # Get category distribution
    categories = db.session.query(
        StoreInventory.category,
        func.count().label('count'),
        func.sum(StoreInventory.quantity * StoreInventory.unit_cost).label('value')
    ).group_by(StoreInventory.category).all()
    
    # Get low stock items
    low_stock = StoreInventory.query.filter(
        StoreInventory.quantity <= StoreInventory.reorder_level
    ).all()
    
    # Prepare data for charts
    category_labels = [c[0] for c in categories]
    category_counts = [c[1] for c in categories]
    category_values = [float(c[2]) for c in categories]
    
    return render_template('inventory/reports.html', 
                         total_items=total_items,
                         total_value=total_value,
                         low_stock_items=low_stock_items,
                         categories=categories,
                         low_stock=low_stock,
                         category_labels=category_labels,
                         category_counts=category_counts,
                         category_values=category_values)


@app.route('/inventory/use', methods=['GET', 'POST'])
@role_required(['super_admin', 'store_keeper'])
def use_inventory_item():
    form = InventoryUsageForm()
    # Populate item choices
    form.item_id.choices = [(item.id, item.name) for item in StoreInventory.query.all()]
    
    if form.validate_on_submit():
        item = StoreInventory.query.get(form.item_id.data)
        if not item:
            flash('Item not found', 'error')
            return redirect(url_for('use_inventory_item'))
            
        if item.quantity < form.quantity.data:
            flash(f'Not enough stock! Only {item.quantity} available', 'error')
            return redirect(url_for('use_inventory_item'))
            
        try:
            # Deduct from inventory
            item.quantity -= form.quantity.data
            
            # Create usage record
            usage = InventoryUsage(
                item_id=item.id,
                quantity_used=form.quantity.data,
                used_by_id=current_user.id,
                notes=form.notes.data
            )
            db.session.add(usage)
            db.session.commit()
            
            flash(f'Used {form.quantity.data} {item.name} from inventory', 'success')
            return redirect(url_for('inventory_list'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Inventory usage error: {str(e)}")
            flash('Error recording inventory usage', 'error')
    
    return render_template('use_inventory.html', form=form)

@app.route('/inventory/request', methods=['GET', 'POST'])
@login_required
def request_inventory_item():
    form = InventoryRequestForm()
    # Populate item choices
    form.item_id.choices = [(item.id, item.name) for item in StoreInventory.query.all()]
    
    if form.validate_on_submit():
        item = StoreInventory.query.get(form.item_id.data)
        if not item:
            flash('Item not found', 'error')
            return redirect(url_for('request_inventory_item'))
            
        try:
            request = InventoryRequest(
                item_id=item.id,
                quantity_requested=form.quantity.data,
                requested_by_id=current_user.id,
                notes=form.notes.data
            )
            db.session.add(request)
            db.session.commit()
            
            flash('Inventory request submitted successfully', 'success')
            return redirect(url_for('inventory_list'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Inventory request error: {str(e)}")
            flash('Error submitting inventory request', 'error')
    
    return render_template('request_inventory.html', form=form)

@app.route('/inventory/requests')
@role_required(['super_admin', 'store_keeper'])
def view_inventory_requests():
    requests = InventoryRequest.query.options(
        db.joinedload(InventoryRequest.item),
        db.joinedload(InventoryRequest.requested_by)
    ).order_by(InventoryRequest.requested_at.desc()).all()
    
    return render_template('inventory_requests.html', requests=requests)

@app.route('/inventory/request/approve/<int:request_id>', methods=['POST'])
@role_required(['super_admin', 'store_keeper'])
def approve_inventory_request(request_id):
    request = InventoryRequest.query.get_or_404(request_id)
    item = StoreInventory.query.get(request.item_id)
    
    if not item:
        flash('Item not found', 'error')
        return redirect(url_for('view_inventory_requests'))
        
    if item.quantity < request.quantity_requested:
        flash(f'Not enough stock to fulfill request! Only {item.quantity} available', 'error')
        return redirect(url_for('view_inventory_requests'))
        
    try:
        # Deduct from inventory
        item.quantity -= request.quantity_requested
        
        # Update request status
        request.status = 'approved'
        request.approved_by_id = current_user.id
        request.approved_at = datetime.utcnow()
        
        # Create usage record
        usage = InventoryUsage(
            item_id=item.id,
            quantity_used=request.quantity_requested,
            used_by_id=request.requested_by_id,
            notes=f"Approved request #{request.id}: {request.notes}"
        )
        db.session.add(usage)
        db.session.commit()
        
        flash('Request approved and inventory updated', 'success')
        return redirect(url_for('view_inventory_requests'))
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Request approval error: {str(e)}")
        flash('Error approving request', 'error')
        return redirect(url_for('view_inventory_requests'))


if __name__ == '__main__':
    with app.app_context():
        # Create all database tables
        db.create_all()
      
        # Initialize roles
        for role_name in initial_roles:
            if not Role.query.filter_by(name=role_name).first():
                role = Role(name=role_name)
                db.session.add(role)
        db.session.commit()
    
    app.run(debug=True)