from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField, SelectField, DateTimeField, DateField  
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError, Regexp, Optional

from models import User, Staff
from datetime import date



from wtforms.validators import DataRequired, Optional, NumberRange

from wtforms import DecimalField, IntegerField, MultipleFileField, SelectMultipleField,FloatField,DateTimeLocalField

from flask_wtf.file import FileField, FileAllowed,  FileRequired  

class UserSettingsForm(FlaskForm):
    dark_mode = BooleanField('Enable Dark Mode')
    font_size = SelectField('Font Size', choices=[
        ('small', 'Small'),
        ('medium', 'Medium'),
        ('large', 'Large')
    ])
    submit = SubmitField('Save Settings')


class InventoryForm(FlaskForm):
    name = StringField('Item Name', validators=[DataRequired()])
    description = TextAreaField('Description')
    category = StringField('Category', validators=[DataRequired()])
    unit = StringField('Unit', validators=[DataRequired()])
    quantity = IntegerField('Quantity', validators=[DataRequired()])
    reorder_level = IntegerField('Reorder Level', validators=[DataRequired()])
    unit_cost = DecimalField('Unit Cost', validators=[DataRequired()])
    supplier = StringField('Supplier')
    submit = SubmitField('Save')

class InventoryUsageForm(FlaskForm):
    item_id = SelectField('Item', coerce=int, validators=[DataRequired()])
    quantity = IntegerField('Quantity to Use', validators=[DataRequired(), NumberRange(min=1)])
    notes = TextAreaField('Notes')
    submit = SubmitField('Use Item')

class InventoryRequestForm(FlaskForm):
    item_id = SelectField('Item', coerce=int, validators=[DataRequired()])
    quantity = IntegerField('Quantity Needed', validators=[DataRequired(), NumberRange(min=1)])  # Correct field name
    notes = TextAreaField('Reason for Request')
    submit = SubmitField('Submit Request')

class RoomForm(FlaskForm):
    # Existing fields
    name = StringField('Room Name', validators=[DataRequired()])
    price = DecimalField('Price', validators=[DataRequired()])
    capacity = IntegerField('Capacity', validators=[DataRequired()])
    size = IntegerField('Size', validators=[DataRequired()])
    bedsize = IntegerField('Bedsize', validators=[DataRequired()])
    room_type = SelectField('Room Type', choices=[
        ('single', 'Single'), 
        ('double', 'Double'), 
        ('suite', 'Suite')
    ])
    floor = SelectField('Floor', choices=[
        ('1', '1st'), 
        ('2', '2nd'), 
        ('3', '3rd')
    ])
    description = TextAreaField('Description')
    amenities = SelectMultipleField('Amenities', choices=[
        ('wifi', 'WiFi'), 
        ('ac', 'AC'), 
        ('refrigirator', 'REFRIGIRATOR'), 
         ('electric jug', 'ELECTRIC JUG'), 
        ('tv', 'TV'),
         ('water heater', 'WATER HEATER'),
        ('standard wardrobe', 'STANDARD WARDROBE')
    ])
    images = MultipleFileField('Room Images')
    
 
    primary_image = SelectField('Primary Image', choices=[], validate_choice=False)  # Initialize with empty list

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Update choices dynamically
        if 'obj' in kwargs and kwargs['obj']:
            room = kwargs['obj']
            self.primary_image.choices = [(img.id, img.filename) for img in room.images]
            self.primary_image.choices.insert(0, (-1, 'No Primary Image'))

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')


class BookingForm(FlaskForm):
    check_in_date = DateField('Check-in Date', format='%Y-%m-%d', validators=[DataRequired()])
    check_out_date = DateField('Check-out Date', format='%Y-%m-%d', validators=[DataRequired()])
    submit = SubmitField('Book Room')

class NotificationForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=100)])
    message = TextAreaField('Message', validators=[DataRequired()])
    category = SelectField('Category', choices=[
        
    ])
    
    submit = SubmitField('Send Notification')




class NotificationForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    message = TextAreaField('Message', validators=[DataRequired()])
    category = SelectField('Category', choices=[
        ('general', 'General'),
        ('alert', 'Alert'),
        ('promotion', 'Promotion'),
        ('system', 'System')
    ], default='general')
    
    send_to = SelectField('Filter By', choices=[
        ('all', 'All Users'),
        ('role', 'By Role'),
        ('custom', 'Specific Users'),
        ('new_users', 'New Users'),
        ('frequent_customers', 'Frequent Customers'),
        ('inactive_users', 'Inactive Users'),
        ('high_value', 'High Value Customers'),
        ('room_type', 'Room Type Bookers'),
        ('no_bookings', 'Never Booked Users'),
        ('recent_activity', 'Recent Activity')
    ], default='all')
    
    # Filter parameters
    roles = SelectMultipleField('Roles', coerce=int)
    custom_users = SelectMultipleField('Users', coerce=int)
    days_threshold = IntegerField('Days Threshold', validators=[Optional()])
    min_bookings = IntegerField('Minimum Bookings', validators=[Optional()])
    inactive_days = IntegerField('Inactive Days', validators=[Optional()])
    min_spending = DecimalField('Minimum Spending', places=2, validators=[Optional()])
    room_types = SelectMultipleField('Room Types', choices=[
        ('single', 'Single'),
        ('double', 'Double'),
        ('suite', 'Suite')
    ])
    last_activity_days = IntegerField('Days Since Last Activity', validators=[Optional()])
    
    expires_at = DateTimeField('Expiration Date', format='%Y-%m-%d %H:%M', validators=[Optional()])
    
    submit = SubmitField('Create Notification')



class AdminRegistrationForm(FlaskForm):
    email = StringField('Email', validators=[
        DataRequired(), 
        Email(),
        Length(max=120)
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8),
        #Regexp(r'^(?=.*[A-Z])(?=.*[!@#$%^&*])', 
               #message='Must contain at least 1 uppercase and 1 special character')
    ])
    confirm_password = PasswordField(
        'Confirm Password',
        validators=[DataRequired(), EqualTo('password')]
    )
    submit = SubmitField('Register Admin Account')  # Match button text
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, validators

class ContactForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    subject = StringField('Subject', validators=[DataRequired()])
    message = TextAreaField('Message', validators=[DataRequired()])
    submit = SubmitField('Send Message')

class ResetPasswordRequestForm(FlaskForm):
    email = StringField('Email', validators=[
        validators.DataRequired(),
        validators.Email()
    ])
    submit = SubmitField('Reset Password')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[
        validators.DataRequired(),
        validators.Length(min=8)
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        validators.DataRequired(),
        validators.EqualTo('password')
    ])
    submit = SubmitField('Change Password')

class AdminLoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class AutomationForm(FlaskForm):
    name = StringField('Rule Name', validators=[DataRequired()])
    trigger_type = SelectField('Trigger Type', choices=[
        ('date', 'Specific Date'),
        ('event', 'System Event'),
        ('interval', 'Recurring Interval')
    ])
    action_type = SelectField('Action Type', choices=[
        ('email', 'Send Email'),
        ('notification', 'Create Notification'),
        ('status', 'Update Status')
    ])
    is_active = BooleanField('Active', default=True)
    submit = SubmitField('Save Automation')

class ReportForm(FlaskForm):
    report_type = SelectField('Report Type', choices=[
        ('daily', 'Daily Summary'),
        ('monthly', 'Monthly Analytics'),
        ('custom', 'Custom Report')
    ], validators=[DataRequired()])
    start_date = DateField('Start Date', format='%Y-%m-%d', validators=[Optional()])
    end_date = DateField('End Date', format='%Y-%m-%d', validators=[Optional()])
    report_format = SelectField('Format', choices=[
        ('pdf', 'PDF'), 
        ('csv', 'CSV'), 
        ('excel', 'Excel')
    ], validators=[DataRequired()])
    submit = SubmitField('Generate Report')

    def validate(self, **kwargs):
        # Run default validators first
        if not super().validate():
            return False

        # Custom validation for report type
        if self.report_type.data == 'custom':
            if not self.start_date.data:
                self.start_date.errors.append('Start date is required for custom reports.')
                return False
            if not self.end_date.data:
                self.end_date.errors.append('End date is required for custom reports.')
                return False
            if self.start_date.data > self.end_date.data:
                self.end_date.errors.append('End date must be after start date.')
                return False

        return True
    
class BarItemForm(FlaskForm):
    name = StringField('Item Name', validators=[validators.InputRequired()])
    price = FloatField('Price', validators=[
        validators.InputRequired(),
        validators.NumberRange(min=0.01)
    ])
    quantity = IntegerField('Initial Stock', validators=[  # Changed from stock_quantity
        validators.InputRequired(),
        validators.NumberRange(min=0)
    ])

    image = FileField('Item Image', validators=[
        Optional(),
        FileAllowed(['jpg', 'jpeg', 'png', 'gif'], 'Images only!')
    ])



class ExpenseForm(FlaskForm):
    date = DateField('Expense Date', validators=[DataRequired()], default=date.today)
    amount = FloatField('Amount', validators=[DataRequired(), NumberRange(min=0.01)])
    category = SelectField('Category', choices=[
        ('food', 'Food & Beverage'),
        ('electronics', 'Electronics'),
        ('furniture', 'Furniture & Fixtures'),
        ('cleaning', 'Cleaning Supplies'),
        ('maintenance', 'Maintenance & Repairs'),
        ('utilities', 'Utilities'),
        ('salaries', 'Salaries'),
        ('marketing', 'Marketing'),
        ('other', 'Other')
    ], validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    vendor = StringField('Vendor')
    payment_method = SelectField('Payment Method', choices=[
        ('cash', 'Cash'),
        ('card', 'Credit/Debit Card'),
        ('transfer', 'Bank Transfer'),
        ('cheque', 'Cheque')
    ], validators=[DataRequired()])
    document = FileField('Receipt/Invoice')
    submit = SubmitField('Record Expense')

class RegistrationForm(FlaskForm):
    first_name = StringField('First Name', validators=[
        DataRequired(),
        Length(min=2, max=25)
    ])
    last_name = StringField('Last Name', validators=[
        DataRequired(),
        Length(min=2, max=25)
    ])
    phone_number = StringField('Phone Number', validators=[
        DataRequired(),
        Length(min=10, max=15),
        Regexp(r'^[0-9]+$', message="Phone number must contain only digits")
    ])
    email = StringField('Email', validators=[
        DataRequired(),
        Email(),
        Length(max=50)
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=6)
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password')
    ])
    submit = SubmitField('Register')

class EditProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('New Password')
    submit = SubmitField('Update Profile')

    def __init__(self, original_username, *args, **kwargs):
        super(EditProfileForm, self).__init__(*args, **kwargs)
        self.original_username = original_username

    def validate_username(self, field):
        if field.data != self.original_username:
            if User.query.filter_by(username=field.data).first():
                raise ValidationError('Username already in use.')

class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    body = TextAreaField('Body', validators=[DataRequired()])
    submit = SubmitField('Post')




class StaffRegistrationForm(FlaskForm):
    first_name = StringField('First Name', validators=[
        DataRequired(),
        Length(min=2, max=50),
        Regexp(r'^[A-Za-z]+$', message="First name must contain only letters")
    ])
    last_name = StringField('Last Name', validators=[
        DataRequired(),
        Length(min=2, max=50),
        Regexp(r'^[A-Za-z]+$', message="Last name must contain only letters")
    ])
   
    role = SelectField('Role', choices=[
        ('receptionist', 'Receptionist'),
        ('hr', 'HR'),
        ('bar_staff', 'Bar Staff'),
        ('staff', 'Staff'),
        ('api_management', 'API Management'),
        ('finance_admin', 'Finance Admin'),
        ('bar_manager', 'Bar Manager'),
        ('super_admin', 'Super Admin'),
        ('housekeeping_supervisor', 'Housekeeping Supervisor'),
        ('store_keeper', 'Store_Keeper')
    ], validators=[DataRequired()])
    
    # KEY CHANGE: Added 'None' option to position
    position = SelectField('Position', choices=[
        ('None', 'No Position'),
        ('Front Desk Agent', 'Front Desk Agent'),
        ('Receptionist', 'Receptionist'),
        ('Concierge', 'Concierge'),
        ('Housekeeper', 'Housekeeper'),
        ('Bellhop', 'Bellhop'),
        ('Night Auditor', 'Night Auditor'),
        ('Maintenance', 'Maintenance'),
        ('Security', 'Security'),
        ('Manager', 'Manager'),
        ('General Manager', 'General Manager'),
        ('Restaurant Staff', 'Restaurant Staff'),
        ('Chef', 'Chef'),
        ('Waiter', 'Waiter'),
        ('Bartender', 'Bartender'),
        ('Porter', 'Porter'),
        ('Valet', 'Valet'),
        ('Laundry Staff', 'Laundry Staff'),
        ('Event Coordinator', 'Event Coordinator'),
        ('Spa Staff', 'Spa Staff'),
        ('Other', 'Other')
    ], validators=[DataRequired()])
    
    email = StringField('Email', validators=[
        DataRequired(),
        Email(message="Invalid email address")
    ])
    phone_number = StringField('Phone Number', validators=[
        DataRequired(),
        Length(min=10, max=15),
        Regexp(r'^[0-9]+$', message="Phone number must contain only digits")
    ])
    profile_image = FileField('Profile Image', validators=[
        Optional(),
        FileAllowed(['jpg', 'png', 'jpeg', 'gif'], 'Images only!')
    ])
    password = PasswordField('Password', validators=[
        Optional(),
        Length(min=8)
    ])
    confirm_password = PasswordField(
        'Confirm Password',
        validators=[
            Optional(),
            EqualTo('password', message='Passwords must match')
        ]
    )
    submit = SubmitField('Register Staff')

    def __init__(self, original_staff_id=None, original_email=None, original_phone=None, *args, **kwargs):
        super(StaffRegistrationForm, self).__init__(*args, **kwargs)
        self.original_staff_id = original_staff_id
        self.original_email = original_email
        self.original_phone = original_phone

  

    def validate_email(self, field):
        if field.data != self.original_email:
            staff = Staff.query.filter_by(email=field.data).first()
            if staff is not None:
                raise ValidationError('Email already registered.')

    def validate_phone_number(self, field):
        if field.data != self.original_phone:
            staff = Staff.query.filter_by(phone_number=field.data).first()
            if staff is not None:
                raise ValidationError('Phone number already registered.')

class StaffEditForm(FlaskForm):
    first_name = StringField('First Name', validators=[
        Optional(),
        Length(min=2, max=50),
        Regexp(r'^[A-Za-z\s]+$', message="First name must contain only letters")
    ])
    last_name = StringField('Last Name', validators=[
        Optional(),
        Length(min=2, max=50),
        Regexp(r'^[A-Za-z\s]+$', message="Last name must contain only letters")
    ])
    
    role = SelectField('Role', choices=[
        ('receptionist', 'Receptionist'),
        ('hr', 'HR'),
        ('bar_staff', 'Bar Staff'),
        ('staff', 'Staff'),
        ('api_management', 'API Management'),
        ('finance_admin', 'Finance Admin'),
        ('bar_manager', 'Bar Manager'),
        ('super_admin', 'Super Admin'),
        ('housekeeping_supervisor', 'Housekeeping Supervisor')
    ], validators=[Optional()])
    
    # KEY CHANGE: Added 'None' option to position
    position = SelectField('Position', choices=[
        ('None', 'No Position'),
        ('Front Desk Agent', 'Front Desk Agent'),
        ('Receptionist', 'Receptionist'),
        ('Concierge', 'Concierge'),
        ('Housekeeper', 'Housekeeper'),
        ('Bellhop', 'Bellhop'),
        ('Night Auditor', 'Night Auditor'),
        ('Maintenance', 'Maintenance'),
        ('Security', 'Security'),
        ('Manager', 'Manager'),
        ('General Manager', 'General Manager'),
        ('Restaurant Staff', 'Restaurant Staff'),
        ('Chef', 'Chef'),
        ('Waiter', 'Waiter'),
        ('Bartender', 'Bartender'),
        ('Porter', 'Porter'),
        ('Valet', 'Valet'),
        ('Laundry Staff', 'Laundry Staff'),
        ('Event Coordinator', 'Event Coordinator'),
        ('Spa Staff', 'Spa Staff'),
        ('Other', 'Other')
    ], validators=[Optional()])
    
    email = StringField('Email', validators=[
        DataRequired(),
        Email(),
        Length(max=120)
    ])
    phone_number = StringField('Phone Number', validators=[
        Optional(),
        Length(min=10, max=15),
        Regexp(r'^[0-9]+$', message="Phone number must contain only digits")
    ])
    profile_image = FileField('Profile Image', validators=[
        Optional(),
        FileAllowed(['jpg', 'png', 'jpeg'], 'Images only!')
    ])
    submit = SubmitField('Update Staff')

    def __init__(self, original_staff_id, original_email, original_phone, *args, **kwargs):
        super(StaffEditForm, self).__init__(*args, **kwargs)
        self.original_staff_id = original_staff_id
        self.original_email = original_email
        self.original_phone = original_phone

    

    def validate_email(self, field):
        if field.data != self.original_email:
            staff = Staff.query.filter_by(email=field.data).first()
            if staff:
                raise ValidationError('Email already registered.')

    def validate_phone_number(self, field):
        if field.data != self.original_phone:
            staff = Staff.query.filter_by(phone_number=field.data).first()
            if staff:
                raise ValidationError('Phone number already registered.')
            
from wtforms import IntegerField, TextAreaField, SubmitField
from wtforms.validators import InputRequired, NumberRange

# Add new form in forms.py (if not already present)
class RatingForm(FlaskForm):
    rating = IntegerField('Rating', validators=[
        InputRequired(),
        NumberRange(min=1, max=5, message='Rating must be between 1-5 stars')
    ])
    comment = TextAreaField('Comment (Optional)')
    submit = SubmitField('Submit Rating')
