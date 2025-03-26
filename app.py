from flask import Flask, render_template, request, redirect, url_for, flash, session, Response, jsonify
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SelectField, IntegerField, SubmitField, PasswordField, RadioField
from wtforms.validators import DataRequired, Length, ValidationError, Regexp
import mysql.connector
from mysql.connector import pooling
import logging
import os
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from flask_socketio import SocketIO
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, CSRFError
import csv
from io import StringIO
import json
import bleach
from functools import wraps

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'my-static-secret-key-12345')  # Static key for development
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Setup logging
logging.basicConfig(
    level=logging.DEBUG,  # Changed to DEBUG for more detail
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(), logging.FileHandler('app.log')]
)
logger = logging.getLogger(__name__)

# Database connection pool
db_config = {
    'pool_name': 'pharmacy_pool',
    'pool_size': 20,
    'host': os.getenv('MYSQL_HOST', 'localhost'),
    'user': os.getenv('MYSQL_USER', 'root'),
    'password': os.getenv('MYSQL_PASSWORD', ''),
    'database': 'pharmacy_exam',
    'raise_on_warnings': True,
    'autocommit': False,
    'use_pure': True,
    'connection_timeout': 30
}

connection_pool = None

def get_db_connection():
    global connection_pool
    try:
        if connection_pool is None:
            connection_pool = pooling.MySQLConnectionPool(**db_config)
            logger.debug("Created DB connection pool")
        conn = connection_pool.get_connection()
        if conn.is_connected():
            logger.debug("Database connection established successfully")
            return conn
    except mysql.connector.Error as err:
        logger.error(f"Database connection error: {str(err)}")
        return None

# Initialize Flask-SocketIO
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# Initialize Flask-Limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Security helpers
def sanitize_input(text):
    """Clean user input to prevent XSS"""
    if text is None:
        return None
    return bleach.clean(str(text), strip=True)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        logger.debug(f"Session in login_required: {session}")
        if 'username' not in session:
            logger.warning(f"Access to {request.path} rejected - user not logged in")
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('choose_login'))
        return f(*args, **kwargs)
    return decorated_function

def super_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session or session.get('role') != 'super_admin':
            flash('Super admin privileges required.', 'danger')
            return redirect(url_for('choose_login'))
        return f(*args, **kwargs)
    return decorated_function

def institute_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        logger.debug(f"Session in institute_admin_required: {session}")
        if 'username' not in session:
            logger.warning(f"Access to {request.path} rejected - user not logged in")
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('choose_login'))
            
        if session.get('role') != 'institute_admin':
            logger.warning(f"Access to {request.path} rejected - user {session.get('username')} is not an institute_admin")
            flash('Institute admin privileges required.', 'danger')
            # Redirect to an appropriate page based on role
            if session.get('role') in ['individual_user', 'student_user']:
                return redirect(url_for('user_dashboard'))
            return redirect(url_for('choose_login'))
            
        if not session.get('institution_id'):
            logger.error(f"institute_admin missing institution_id: {session}")
            flash('Institution not found. Please log in again.', 'danger')
            session.clear()
            return redirect(url_for('choose_login'))
            
        return f(*args, **kwargs)
    return decorated_function

def quiz_access_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session or session.get('role') not in ['individual_user', 'student_user', 'institute_admin', 'super_admin']:
            flash('Please log in to access quizzes.', 'danger')
            return redirect(url_for('choose_login'))
        return f(*args, **kwargs)
    return decorated_function

def any_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session or session.get('role') not in ['institute_admin', 'super_admin']:
            flash('Admin privileges required.', 'danger')
            return redirect(url_for('choose_login'))
        return f(*args, **kwargs)
    return decorated_function


# Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=50)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=50)])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=50)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=50)])
    submit = SubmitField('Register')

class QuestionForm(FlaskForm):
    question = TextAreaField('Question', validators=[DataRequired(), Length(min=10, max=1000)])
    option_a = StringField('Option A', validators=[DataRequired(), Length(max=100)])
    option_b = StringField('Option B', validators=[DataRequired(), Length(max=100)])
    option_c = StringField('Option C', validators=[DataRequired(), Length(max=100)])
    option_d = StringField('Option D', validators=[DataRequired(), Length(max=100)])
    correct_answer = SelectField('Correct Answer', choices=[('a', 'A'), ('b', 'B'), ('c', 'C'), ('d', 'D')], validators=[DataRequired()])
    category = StringField('Category', validators=[DataRequired(), Length(max=50)])
    difficulty = SelectField('Difficulty', choices=[('easy', 'Easy'), ('medium', 'Medium'), ('hard', 'Hard')], validators=[DataRequired()])
    exam_name = StringField('Exam Name', validators=[DataRequired(), Length(max=100)])
    subject = StringField('Subject', validators=[DataRequired(), Length(max=100)])
    topics = StringField('Topics (comma-separated)', validators=[DataRequired(), Length(max=255)])
    year = IntegerField('Year', validators=[DataRequired()])
    explanation = TextAreaField('Explanation', validators=[DataRequired(), Length(min=10, max=1000)])
    submit = SubmitField('Submit Question')

class UserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=50)])
    role = SelectField('Role', choices=[('individual_user', 'Individual User'), ('student_user', 'Student User'), ('institute_admin', 'Institute Admin'), ('super_admin', 'Super Admin')], validators=[DataRequired()])
    status = SelectField('Status', choices=[('active', 'Active'), ('inactive', 'Inactive')], validators=[DataRequired()])
    password = PasswordField('New Password (leave blank to keep unchanged)', validators=[Length(min=0, max=50)])
    submit = SubmitField('Update User')

class InstitutionRegisterForm(FlaskForm):
    institution_name = StringField('Institution Name', validators=[DataRequired(), Length(min=3, max=255)])
    admin_name = StringField('Admin Name', validators=[DataRequired(), Length(min=3, max=50)])
    email = StringField('Email Address', validators=[DataRequired(), Regexp(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', message='Invalid email address')])
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=50)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=50)])
    subscription_plan = SelectField('Subscription Plan', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Register Institution')

class StudentRegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=50)])
    email = StringField('Email', validators=[DataRequired(), Regexp(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', message='Invalid email address')])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=50)])
    institution_code = StringField('Institution Code', validators=[DataRequired(), Length(min=6, max=20)])
    submit = SubmitField('Register as Student')

class LoginTypeForm(FlaskForm):
    login_type = RadioField('Login Type', choices=[
        ('individual', 'Individual Login'), 
        ('institution', 'Institution Admin'), 
        ('student', 'Institution Student')
    ], validators=[DataRequired()])
    submit = SubmitField('Continue')

class InstitutionLoginForm(FlaskForm):
    institution_code = StringField('Institution Code', validators=[DataRequired(), Length(min=6, max=20)])
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=50)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=50)])
    submit = SubmitField('Login')

class AddStudentForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=50)])
    email = StringField('Email', validators=[DataRequired(), Regexp(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', message='Invalid email address')])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=50)])
    submit = SubmitField('Add Student')

class SubscriptionForm(FlaskForm):
    plan_id = RadioField('Plan', coerce=int, validators=[DataRequired()])
    payment_method = SelectField('Payment Method', 
                                choices=[('credit_card', 'Credit Card'), 
                                        ('paypal', 'PayPal')],
                                validators=[DataRequired()])
    submit = SubmitField('Subscribe Now')

# Database Initialization
def init_db():
    try:
        conn = mysql.connector.connect(
            host=db_config['host'],
            user=db_config['user'],
            password=db_config['password']
        )
        cursor = conn.cursor()
        cursor.execute("CREATE DATABASE IF NOT EXISTS pharmacy_exam")
        cursor.execute("USE pharmacy_exam")
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            role ENUM('individual_user', 'student_user', 'institute_admin', 'super_admin') DEFAULT 'individual_user',
            status ENUM('active', 'inactive') DEFAULT 'active',
            last_active DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_username (username),
            INDEX idx_role (role),
            INDEX idx_status (status),
            INDEX idx_last_active (last_active)
        )''')
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS questions (
            id INT AUTO_INCREMENT PRIMARY KEY,
            question TEXT NOT NULL,
            option_a VARCHAR(100) NOT NULL,
            option_b VARCHAR(100) NOT NULL,
            option_c VARCHAR(100) NOT NULL,
            option_d VARCHAR(100) NOT NULL,
            correct_answer CHAR(1) NOT NULL,
            category VARCHAR(50) NOT NULL,
            difficulty ENUM('easy', 'medium', 'hard') DEFAULT 'medium',
            exam_name VARCHAR(100) NOT NULL,
            subject VARCHAR(100) NOT NULL,
            topics VARCHAR(255) NOT NULL,
            year INT NOT NULL,
            explanation TEXT NOT NULL,
            created_by INT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
            INDEX idx_exam_year (exam_name, year),
            INDEX idx_subject (subject),
            INDEX idx_difficulty (difficulty),
            INDEX idx_category (category),
            INDEX idx_created_at (created_at)
        )''')
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS results (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            score INT NOT NULL,
            total_questions INT NOT NULL,
            time_taken INT NOT NULL,
            answers JSON,
            date_taken DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            INDEX idx_user_id (user_id),
            INDEX idx_date_taken (date_taken)
        )''')
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS question_reviews (
            id INT AUTO_INCREMENT PRIMARY KEY,
            question_id INT NOT NULL,
            user_id INT NOT NULL,
            comment TEXT,
            rating INT NOT NULL CHECK (rating >= 1 AND rating <= 5),
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (question_id) REFERENCES questions(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            INDEX idx_question_id (question_id),
            INDEX idx_user_id (user_id),
            INDEX idx_rating (rating)
        )''')
        
        cursor.execute('SELECT COUNT(*) FROM users WHERE role = "super_admin"')
        if cursor.fetchone()[0] == 0:
            admin_password = os.getenv('ADMIN_PASSWORD', 'admin123')
            cursor.execute('INSERT INTO users (username, password, role, status) VALUES (%s, %s, %s, %s)',
                          ('superadmin', generate_password_hash(admin_password), 'super_admin', 'active'))
            logger.info("Super admin user created successfully")
        
        conn.commit()
        logger.info("Database initialized successfully")
    except mysql.connector.Error as err:
        logger.error(f"Database initialization error: {str(err)}")
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()

# Routes
@app.route('/')
def index():
    """
    Main index route with improved redirect handling and debug logging
    """
    logger.debug(f"Session data: {session}")
    
    if 'username' in session:
        role = session.get('role')
        
        # Check if role is valid to avoid redirect loops
        if role not in ['super_admin', 'institute_admin', 'individual_user', 'student_user']:
            logger.error(f"Invalid role in session: {role}")
            session.clear()
            flash('Invalid user role. Please log in again.', 'danger')
            return redirect(url_for('choose_login'))
            
        if role == 'super_admin':
            return redirect(url_for('admin_dashboard'))
        elif role == 'institute_admin':
            return redirect(url_for('institution_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))
    
    return redirect(url_for('choose_login'))

@app.route('/ping')
def ping():
    """
    Endpoint to check if the user session is still valid
    Returns JSON with authentication status
    """
    is_authenticated = 'username' in session
    return jsonify({
        'authenticated': is_authenticated,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/choose_login', methods=['GET', 'POST'])
def choose_login():
    form = LoginTypeForm()
    if form.validate_on_submit():
        login_type = form.login_type.data
        if login_type == 'individual':
            return redirect(url_for('login'))
        elif login_type == 'institution':
            return redirect(url_for('institution_login'))  # This is causing the error
        else:  # login_type == 'student'
            return redirect(url_for('student_login'))
    return render_template('choose_login.html', form=form)

@app.route('/register_institution', methods=['GET', 'POST'])
def register_institution():
    form = InstitutionRegisterForm()
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute('SELECT id, name, price, max_users FROM subscription_plans WHERE is_institution = TRUE')
    plans = cursor.fetchall()
    form.subscription_plan.choices = [(plan['id'], f"{plan['name']} (${plan['price']} - Up to {plan['max_users']} users)") for plan in plans]
    
    if form.validate_on_submit():
        institution_name = sanitize_input(form.institution_name.data)
        admin_name = sanitize_input(form.admin_name.data)
        email = sanitize_input(form.email.data)
        username = sanitize_input(form.username.data)
        password = form.password.data
        plan_id = form.subscription_plan.data
        
        cursor.execute('SELECT * FROM subscription_plans WHERE id = %s', (plan_id,))
        plan = cursor.fetchone()
        if not plan:
            flash('Invalid subscription plan selected.', 'danger')
            return redirect(url_for('register_institution'))
        
        import random
        import string
        institution_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        
        try:
            cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
            if cursor.fetchone():
                flash('Username already exists. Please choose a different one.', 'danger')
                return render_template('register_institution.html', form=form)
            
            if not conn.in_transaction:
                conn.start_transaction()
            
            hashed_password = generate_password_hash(password)
            cursor.execute('''INSERT INTO users 
                (username, email, password, role, status, user_type, last_active) 
                VALUES (%s, %s, %s, %s, %s, %s, %s)''',
                (username, email, hashed_password, 'institute_admin', 'active', 'institution_admin', datetime.now()))
            admin_id = cursor.lastrowid
            
            start_date = datetime.now()
            end_date = start_date + timedelta(days=plan['duration_days'])
            
            cursor.execute('''INSERT INTO institutions
                (name, admin_id, subscription_plan_id, user_limit, subscription_start, subscription_end, status, institution_code)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)''',
                (institution_name, admin_id, plan_id, plan['max_users'], start_date, end_date, 'active', institution_code))
            institution_id = cursor.lastrowid
            
            cursor.execute('''UPDATE users
                SET institution_id = %s,
                    subscription_plan_id = %s,
                    subscription_start = %s,
                    subscription_end = %s
                WHERE id = %s''',
                (institution_id, plan_id, start_date, end_date, admin_id))
            
            cursor.execute('''INSERT INTO subscription_history
                (institution_id, subscription_plan_id, start_date, end_date)
                VALUES (%s, %s, %s, %s)''',
                (institution_id, plan_id, start_date, end_date))
            
            conn.commit()
            flash(f'Institution registered successfully! Your institution code is: {institution_code}.', 'success')
            logger.info(f"New institution registered: {institution_name}")
            return redirect(url_for('login'))
            
        except mysql.connector.Error as err:
            if conn.in_transaction:
                conn.rollback()
            logger.error(f"Database error during institution registration: {str(err)}")
            flash('An error occurred during registration.', 'danger')
    
    return render_template('register_institution.html', form=form)

@app.route('/institution_login', methods=['GET', 'POST'])
def institution_login():
    form = InstitutionLoginForm()
    if form.validate_on_submit():
        institution_code = sanitize_input(form.institution_code.data)
        username = sanitize_input(form.username.data)
        password = form.password.data
        
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        try:
            cursor.execute('SELECT * FROM institutions WHERE institution_code = %s', (institution_code,))
            institution = cursor.fetchone()
            
            if not institution:
                flash('Institution not found.', 'danger')
                return render_template('institution_login.html', form=form)
            
            cursor.execute('''SELECT * FROM users 
                WHERE username = %s 
                AND institution_id = %s 
                AND role = 'institute_admin' ''',
                (username, institution['id']))
            user = cursor.fetchone()
            
            if user and check_password_hash(user['password'], password) and user['status'] == 'active':
                session.clear()
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = 'institute_admin'
                session['institution_id'] = institution['id']
                session['institution_name'] = institution['name']
                session.permanent = True
                
                cursor.execute('UPDATE users SET last_active = %s WHERE id = %s',
                              (datetime.now(), user['id']))
                conn.commit()
                
                logger.info(f"Institution admin {username} logged in")
                return redirect(url_for('institution_dashboard'))
            else:
                flash('Invalid credentials or inactive account', 'danger')
        except mysql.connector.Error as err:
            logger.error(f"Database error during institution login: {str(err)}")
            flash('An error occurred during login.', 'danger')
        finally:
            cursor.close()
            conn.close()
    
    return render_template('institution_login.html', form=form)

@app.route('/institution_dashboard')
@institute_admin_required
def institution_dashboard():
    logger.debug(f"institution_dashboard - Session: {session}")
    
    institution_id = session.get('institution_id')
    if not institution_id:
        logger.error(f"Missing institution_id in session for user {session.get('username')}")
        flash('Institution not found. Please log in again.', 'danger')
        session.clear()
        return redirect(url_for('choose_login'))
    
    conn = get_db_connection()
    if conn is None:
        flash('Database connection error.', 'danger')
        return redirect(url_for('index'))
        
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Get institution details
        cursor.execute('SELECT * FROM institutions WHERE id = %s', (institution_id,))
        institution = cursor.fetchone()
        
        if not institution:
            logger.error(f"Institution {institution_id} not found in database")
            flash('Institution not found.', 'danger')
            session.clear()
            return redirect(url_for('choose_login'))
        
        # Get subscription details
        cursor.execute('SELECT * FROM subscription_plans WHERE id = %s', (institution['subscription_plan_id'],))
        subscription = cursor.fetchone()
        
        # Get student count
        cursor.execute('SELECT COUNT(*) as count FROM users WHERE institution_id = %s AND user_type = "institution_student"', (institution_id,))
        student_count = cursor.fetchone()['count']
        
        # Get active students (example definition - modify as needed)
        cursor.execute('''SELECT COUNT(*) as count 
                         FROM users 
                         WHERE institution_id = %s 
                         AND user_type = "institution_student" 
                         AND last_active > %s''', 
                      (institution_id, datetime.now() - timedelta(days=30)))
        active_students = cursor.fetchone()['count']
        
        # Get recent results with username joined
        cursor.execute('''SELECT r.*, u.username 
                         FROM results r 
                         JOIN users u ON r.user_id = u.id 
                         WHERE u.institution_id = %s 
                         ORDER BY r.date_taken DESC 
                         LIMIT 5''', 
                      (institution_id,))
        recent_results = cursor.fetchall()
        
        # Get student performance
        cursor.execute('''SELECT AVG(r.score / r.total_questions * 100) as avg_score 
                         FROM results r 
                         JOIN users u ON r.user_id = u.id 
                         WHERE u.institution_id = %s''', 
                      (institution_id,))
        avg_score_result = cursor.fetchone()
        student_performance = avg_score_result['avg_score'] if avg_score_result and avg_score_result['avg_score'] is not None else 0
        
        # Get students list with additional metrics
        cursor.execute('''SELECT u.*, 
                           COUNT(DISTINCT r.id) as quiz_count,
                           AVG(r.score / r.total_questions * 100) as avg_score,
                           MAX(r.date_taken) as last_quiz_date
                         FROM users u 
                         LEFT JOIN results r ON u.id = r.user_id
                         WHERE u.institution_id = %s 
                         AND u.user_type = "institution_student" 
                         GROUP BY u.id
                         ORDER BY u.username''', 
                      (institution_id,))
        students = cursor.fetchall()
        
        # Format data for display
        for student in students:
            student['avg_score'] = round(student['avg_score'], 1) if student['avg_score'] is not None else 0
            if student['last_active']:
                diff = datetime.now() - student['last_active']
                if diff.days > 0:
                    student['last_active_str'] = f"{diff.days} days ago"
                elif diff.seconds >= 3600:
                    student['last_active_str'] = f"{diff.seconds // 3600} hours ago"
                elif diff.seconds >= 60:
                    student['last_active_str'] = f"{diff.seconds // 60} minutes ago"
                else:
                    student['last_active_str'] = "Just now"
            else:
                student['last_active_str'] = "Never"
        
    except mysql.connector.Error as err:
        logger.error(f"Database error in institution dashboard: {str(err)}")
        flash('Error retrieving dashboard data.', 'danger')
        return redirect(url_for('index'))
    finally:
        cursor.close()
        conn.close()

    form = AddStudentForm()
    return render_template('institution_dashboard.html',
                          institution=institution,
                          subscription=subscription,
                          student_count=student_count,
                          active_students=active_students,
                          recent_results=recent_results,
                          student_performance=student_performance,
                          students=students,
                          remaining_slots=institution['user_limit'] - student_count,
                          form=form)

@app.route('/student_login', methods=['GET', 'POST'])
def student_login():
    form = InstitutionLoginForm()
    if form.validate_on_submit():
        institution_code = sanitize_input(form.institution_code.data)
        username = sanitize_input(form.username.data)
        password = form.password.data
        
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        try:
            cursor.execute('SELECT * FROM institutions WHERE institution_code = %s', (institution_code,))
            institution = cursor.fetchone()
            
            if not institution:
                flash('Institution not found.', 'danger')
                return render_template('student_login.html', form=form)
            
            cursor.execute('''SELECT * FROM users 
                WHERE username = %s 
                AND institution_id = %s 
                AND user_type = 'institution_student' ''',
                (username, institution['id']))
            user = cursor.fetchone()
            
            if user and check_password_hash(user['password'], password) and user['status'] == 'active':
                session.clear()
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = 'student_user'
                session['user_type'] = user['user_type']
                session['institution_id'] = institution['id']
                session['institution_name'] = institution['name']
                session.permanent = True
                
                cursor.execute('UPDATE users SET last_active = %s WHERE id = %s',
                              (datetime.now(), user['id']))
                conn.commit()
                
                logger.info(f"Institution student {username} logged in")
                return redirect(url_for('user_dashboard'))
            else:
                flash('Invalid credentials or inactive account', 'danger')
        except mysql.connector.Error as err:
            logger.error(f"Database error during student login: {str(err)}")
            flash('An error occurred during login.', 'danger')
        finally:
            cursor.close()
            conn.close()
    
    return render_template('student_login.html', form=form)

@app.route('/register_student', methods=['GET', 'POST'])
def register_student():
    form = StudentRegisterForm()
    if form.validate_on_submit():
        username = sanitize_input(form.username.data)
        email = sanitize_input(form.email.data)
        password = form.password.data
        institution_code = sanitize_input(form.institution_code.data)
        
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        try:
            cursor.execute('SELECT * FROM institutions WHERE institution_code = %s AND status = "active"', (institution_code,))
            institution = cursor.fetchone()
            
            if not institution:
                flash('Institution not found or not active.', 'danger')
                return render_template('register_student.html', form=form)
            
            cursor.execute('SELECT COUNT(*) as student_count FROM users WHERE institution_id = %s AND user_type = "institution_student"', (institution['id'],))
            student_count = cursor.fetchone()['student_count']
            
            if student_count >= institution['user_limit']:
                flash('Institution has reached its student limit.', 'danger')
                return render_template('register_student.html', form=form)
            
            cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
            if cursor.fetchone():
                flash('Username already exists.', 'danger')
                return render_template('register_student.html', form=form)
            
            hashed_password = generate_password_hash(password)
            cursor.execute('''INSERT INTO users 
                (username, email, password, role, status, user_type, institution_id, last_active) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)''',
                (username, email, hashed_password, 'student_user', 'active', 'institution_student', institution['id'], datetime.now()))
            
            conn.commit()
            flash('Registration successful! You can now log in as a student.', 'success')
            logger.info(f"New student registered: {username} for institution {institution['name']}")
            return redirect(url_for('student_login'))
            
        except mysql.connector.Error as err:
            conn.rollback()
            logger.error(f"Database error during student registration: {str(err)}")
            flash('An error occurred during registration.', 'danger')
        finally:
            cursor.close()
            conn.close()
    
    return render_template('register_student.html', form=form)


@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    logger.error(f"CSRF error: {e}")
    flash("CSRF token validation failed. Please try again.", "danger")
    return render_template('csrf_error.html', reason=e.description), 400


@app.route('/add_student', methods=['GET', 'POST'])
@institute_admin_required
def add_student():
    institution_id = session.get('institution_id')
    
    form = AddStudentForm()
    if form.validate_on_submit():
        username = sanitize_input(form.username.data)
        email = sanitize_input(form.email.data)
        password = form.password.data
        
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        try:
            cursor.execute('SELECT * FROM institutions WHERE id = %s', (institution_id,))
            institution = cursor.fetchone()
            
            cursor.execute('SELECT COUNT(*) as student_count FROM users WHERE institution_id = %s AND user_type = "institution_student"', (institution_id,))
            student_count = cursor.fetchone()['student_count']
            
            if student_count >= institution['user_limit']:
                flash('You have reached your student limit.', 'danger')
                return redirect(url_for('institution_dashboard'))
            
            cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
            if cursor.fetchone():
                flash('Username already exists.', 'danger')
                return render_template('add_student.html', form=form)
            
            hashed_password = generate_password_hash(password)
            cursor.execute('''INSERT INTO users 
                (username, email, password, role, status, user_type, institution_id, last_active) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)''',
                (username, email, hashed_password, 'student_user', 'active', 'institution_student', institution_id, datetime.now()))
            
            conn.commit()
            flash(f'Student {username} added successfully.', 'success')
            logger.info(f"New student {username} added to institution {institution['name']}")
            return redirect(url_for('institution_dashboard'))
            
        except mysql.connector.Error as err:
            conn.rollback()
            logger.error(f"Database error adding student: {str(err)}")
            flash('An error occurred adding the student.', 'danger')
        finally:
            cursor.close()
            conn.close()
    
    return render_template('add_student.html', form=form)

@app.route('/remove_student/<int:student_id>', methods=['POST'])
@institute_admin_required
def remove_student(student_id):
    institution_id = session.get('institution_id')
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute('''SELECT * FROM users 
            WHERE id = %s AND institution_id = %s AND user_type = "institution_student"''',
            (student_id, institution_id))
        student = cursor.fetchone()
        
        if not student:
            flash('Student not found or does not belong to your institution.', 'danger')
            return redirect(url_for('institution_dashboard'))
        
        cursor.execute('DELETE FROM users WHERE id = %s', (student_id,))
        conn.commit()
        
        flash('Student removed successfully.', 'success')
        logger.info(f"Student {student['username']} removed from institution {session['institution_name']}")
        
    except mysql.connector.Error as err:
        conn.rollback()
        logger.error(f"Database error removing student: {str(err)}")
        flash('An error occurred removing the student.', 'danger')
    finally:
        cursor.close()
        conn.close()
    
    return redirect(url_for('institution_dashboard'))

@app.route('/export_institution_data/<format>')
@institute_admin_required
def export_institution_data(format):
    if format not in ['csv', 'pdf']:
        flash('Unsupported export format.', 'danger')
        return redirect(url_for('institution_dashboard'))
    
    institution_id = session.get('institution_id')
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute('''SELECT 
                u.id, u.username, u.email,
                COUNT(r.id) as quizzes_taken,
                AVG(r.score) as avg_score,
                AVG(r.score / r.total_questions * 100) as avg_percentage,
                MAX(r.score / r.total_questions * 100) as highest_percentage,
                MIN(r.score / r.total_questions * 100) as lowest_percentage,
                AVG(r.time_taken) as avg_time,
                MAX(r.date_taken) as last_quiz_date,
                u.last_active
            FROM users u
            LEFT JOIN results r ON u.id = r.user_id
            WHERE u.institution_id = %s 
            AND u.user_type = "institution_student"
            GROUP BY u.id
            ORDER BY u.username''',
            (institution_id,))
        student_data = cursor.fetchall()
        
        if format == 'csv':
            output = StringIO()
            writer = csv.writer(output)
            writer.writerow(['Student ID', 'Username', 'Email', 'Quizzes Taken', 'Average Score', 'Average Percentage', 'Highest Percentage', 'Lowest Percentage', 'Average Time (seconds)', 'Last Quiz Date', 'Last Active'])
            
            for student in student_data:
                writer.writerow([
                    student['id'],
                    student['username'],
                    student['email'],
                    student['quizzes_taken'],
                    round(student['avg_score'], 2) if student['avg_score'] else 0,
                    round(student['avg_percentage'], 2) if student['avg_percentage'] else 0,
                    round(student['highest_percentage'], 2) if student['highest_percentage'] else 0,
                    round(student['lowest_percentage'], 2) if student['lowest_percentage'] else 0,
                    round(student['avg_time'], 2) if student['avg_time'] else 0,
                    student['last_quiz_date'].strftime('%Y-%m-%d %H:%M:%S') if student['last_quiz_date'] else 'Never',
                    student['last_active'].strftime('%Y-%m-%d %H:%M:%S') if student['last_active'] else 'Never'
                ])
            
            return Response(
                output.getvalue(),
                mimetype='text/csv',
                headers={'Content-Disposition': f'attachment; filename=institution_performance_{session["institution_name"]}_{datetime.now().strftime("%Y%m%d")}.csv'}
            )
        else:
            flash('PDF export functionality is coming soon.', 'info')
            return redirect(url_for('institution_dashboard'))
            
    except mysql.connector.Error as err:
        logger.error(f"Database error during export: {str(err)}")
        flash('Error exporting data.', 'danger')
        return redirect(url_for('institution_dashboard'))
    finally:
        cursor.close()
        conn.close()

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def register():
    if 'username' in session:
        return redirect(url_for('index'))
        
    form = RegisterForm()
    if form.validate_on_submit():
        username = sanitize_input(form.username.data)
        password = form.password.data
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'danger')
            return render_template('register.html', form=form)
            
        hashed_password = generate_password_hash(password)
        
        conn = get_db_connection()
        if conn is None:
            flash("Database connection error.", 'danger')
            return redirect(url_for('register'))
            
        cursor = conn.cursor()
        try:
            cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
            if cursor.fetchone():
                flash('Username already exists.', 'danger')
            else:
                cursor.execute('INSERT INTO users (username, password, role, status, last_active) VALUES (%s, %s, %s, %s, %s)',
                              (username, hashed_password, 'individual_user', 'active', datetime.now()))
                conn.commit()
                flash('Registration successful! You can now log in.', 'success')
                logger.info(f"New individual user registered: {username}")
                return redirect(url_for('login'))
        except mysql.connector.Error as err:
            conn.rollback()
            logger.error(f"Database error during registration: {str(err)}")
            flash('An error occurred during registration.', 'danger')
        finally:
            cursor.close()
            conn.close()
            
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
#@limiter.limit("10 per minute")  # Temporarily disabled for testing
def login():
    if 'username' in session:
        logger.debug("User already logged in, redirecting to index")
        return redirect(url_for('index'))
        
    form = LoginForm()
    logger.debug(f"Generated CSRF Token on GET: {form.csrf_token.data}")
    
    if request.method == 'POST':
        received_token = request.form.get('csrf_token')
        logger.debug(f"Received CSRF Token on POST: {received_token}")
        logger.debug(f"Full Form Data: {request.form}")
        
        # Extended validation for debugging
        if not received_token:
            logger.error("No CSRF token received in form data")
            flash('CSRF token missing. Please try again.', 'danger')
            return render_template('login.html', form=form)
            
        if form.validate_on_submit():
            logger.info("Form validated successfully")
            username = sanitize_input(form.username.data)
            password = form.password.data
            
            conn = get_db_connection()
            if conn is None:
                flash("Database connection error.", 'danger')
                return redirect(url_for('login'))
                
            cursor = conn.cursor(dictionary=True)
            try:
                cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
                user = cursor.fetchone()
                
                if user and check_password_hash(user['password'], password) and user['status'] == 'active':
                    session.clear()
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    session['role'] = user['role']
                    session.permanent = True
                    
                    # Add institution data for relevant users
                    if user.get('institution_id'):
                        try:
                            cursor.execute('SELECT id, name FROM institutions WHERE id = %s', (user['institution_id'],))
                            institution = cursor.fetchone()
                            if institution:
                                session['institution_id'] = institution['id']
                                session['institution_name'] = institution['name']
                        except Exception as e:
                            logger.error(f"Error fetching institution data: {str(e)}")
                    
                    cursor.execute('UPDATE users SET last_active = %s WHERE id = %s',
                                  (datetime.now(), user['id']))
                    conn.commit()
                    
                    logger.info(f"User {username} logged in successfully")
                    if user['role'] == 'super_admin':
                        return redirect(url_for('admin_dashboard'))
                    elif user['role'] == 'institute_admin':
                        return redirect(url_for('institution_dashboard'))
                    else:
                        return redirect(url_for('user_dashboard'))
                else:
                    flash('Invalid credentials or inactive account', 'danger')
                    logger.warning(f"Failed login attempt for username: {username}")
            except mysql.connector.Error as err:
                logger.error(f"Database error during login: {str(err)}")
                flash('An error occurred during login.', 'danger')
            finally:
                cursor.close()
                conn.close()
        else:
            logger.debug(f"Form validation failed: {form.errors}")
            if 'csrf_token' in form.errors:
                logger.error(f"CSRF validation failed: {form.errors['csrf_token']}")
                flash('CSRF validation failed. Please try again.', 'danger')
    
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    username = session.get('username', 'Unknown')
    session.clear()
    flash('You have been successfully logged out.', 'success')
    logger.info(f"User {username} logged out")
    return redirect(url_for('choose_login'))

@app.route('/user_dashboard')
@login_required
def user_dashboard():
    conn = get_db_connection()
    if conn is None:
        flash('Database connection error.', 'danger')
        return redirect(url_for('login'))
        
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute('''SELECT id, score, total_questions, time_taken, date_taken 
            FROM results 
            WHERE user_id = %s 
            ORDER BY date_taken DESC 
            LIMIT 5''',
            (session['user_id'],))
        recent_results = cursor.fetchall()
        
        cursor.execute('SELECT COUNT(*) as count FROM questions')
        result = cursor.fetchone()
        total_questions = result['count'] if result and 'count' in result else 0
        
        # Get user's subscription info
        user_subscription = None
        accessible_exams = []
        
        if session.get('role') == 'individual_user':
            cursor.execute('''SELECT u.subscription_plan_id, u.subscription_start, u.subscription_end, p.name as plan_name
                FROM users u
                LEFT JOIN subscription_plans p ON u.subscription_plan_id = p.id
                WHERE u.id = %s''', (session['user_id'],))
            user_subscription = cursor.fetchone()
            
            if user_subscription and user_subscription['subscription_end'] and user_subscription['subscription_end'] > datetime.now():
                cursor.execute('''SELECT exam_name FROM plan_exam_access
                    WHERE plan_id = %s''', (user_subscription['subscription_plan_id'],))
                accessible_exams = [row['exam_name'] for row in cursor.fetchall()]
        
        elif session.get('role') in ['student_user', 'super_admin', 'institute_admin']:
            cursor.execute('SELECT DISTINCT exam_name FROM questions')
            accessible_exams = [row['exam_name'] for row in cursor.fetchall()]
            
        if session.get('role') == 'institute_admin':
            return redirect(url_for('institution_dashboard'))
        elif session.get('role') == 'super_admin':
            return redirect(url_for('admin_dashboard'))
            
        return render_template('user_dashboard.html', 
                            results=recent_results, 
                            total_questions=total_questions,
                            role=session['role'],
                            user_subscription=user_subscription,
                            accessible_exams=accessible_exams)
    except mysql.connector.Error as err:
        logger.error(f"Database error in user dashboard: {str(err)}")
        flash('Error retrieving dashboard data.', 'danger')
        return render_template('user_dashboard.html', 
                            results=[], 
                            total_questions=0,
                            role=session['role'],
                            user_subscription=None,
                            accessible_exams=[])
    finally:
        cursor.close()
        conn.close()

@app.route('/export_user_dashboard/<format>')
@login_required
def export_user_dashboard(format):
    if format not in ['csv', 'pdf']:
        flash('Unsupported export format.', 'danger')
        return redirect(url_for('user_dashboard'))
        
    if format == 'pdf':
        flash('PDF export functionality is coming soon.', 'info')
        return redirect(url_for('user_dashboard'))
        
    conn = get_db_connection()
    if conn is None:
        flash('Database connection error.', 'danger')
        return redirect(url_for('user_dashboard'))
        
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute('''SELECT id, score, total_questions, time_taken, date_taken 
            FROM results 
            WHERE user_id = %s 
            ORDER BY date_taken DESC''',
            (session['user_id'],))
        results = cursor.fetchall()
        
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['Result ID', 'Score', 'Total Questions', 'Percentage', 'Time Taken (seconds)', 'Date Taken'])
        
        for result in results:
            percentage = round((result['score'] / result['total_questions']) * 100, 1) if result['total_questions'] > 0 else 0
            writer.writerow([
                result['id'], 
                result['score'], 
                result['total_questions'], 
                f"{percentage}%",
                result['time_taken'], 
                result['date_taken'].strftime("%Y-%m-%d %H:%M:%S")
            ])
            
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment; filename=user_results_{session["username"]}_{datetime.now().strftime("%Y%m%d")}.csv'}
        )
    except mysql.connector.Error as err:
        logger.error(f"Database error during export: {str(err)}")
        flash('Error exporting data.', 'danger')
        return redirect(url_for('user_dashboard'))
    finally:
        cursor.close()
        conn.close()

@app.route('/admin_dashboard')
@super_admin_required
def admin_dashboard():
    conn = get_db_connection()
    if conn is None:
        flash('Database connection error.', 'danger')
        return redirect(url_for('choose_login'))
        
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute('''SELECT COUNT(*) as count 
            FROM users 
            WHERE last_active > %s''',
            (datetime.now() - timedelta(minutes=30),))
        result = cursor.fetchone()
        active_users = result['count'] if result else 0
        
        cursor.execute('SELECT COUNT(*) as count FROM questions')
        result = cursor.fetchone()
        total_questions = result['count'] if result else 0
        
        cursor.execute('SELECT COUNT(*) as count FROM results')
        result = cursor.fetchone()
        total_quizzes = result['count'] if result else 0
        
        cursor.execute('''SELECT 'question' as type, q.question as content, u.username, q.created_at as date
            FROM questions q
            JOIN users u ON q.created_by = u.id
            UNION ALL
            SELECT 'result' as type, 
                   CONCAT('Score: ', r.score, '/', r.total_questions) as content, 
                   u.username, r.date_taken as date
            FROM results r
            JOIN users u ON r.user_id = u.id
            ORDER BY date DESC
            LIMIT 10''')
        recent_activity = cursor.fetchall()
    except mysql.connector.Error as err:
        logger.error(f"Database error in admin dashboard: {str(err)}")
        flash('Error retrieving dashboard data.', 'danger')
        active_users = 0
        total_questions = 0
        total_quizzes = 0
        recent_activity = []
    finally:
        cursor.close()
        conn.close()
    
    now = datetime.now()
        
    return render_template('admin_dashboard.html', 
                          active_users=active_users,
                          total_questions=total_questions, 
                          total_quizzes=total_quizzes,
                          recent_activity=recent_activity,
                          now=now)

@app.route('/results')
@login_required
def results():
    result_id = request.args.get('result_id', type=int)
    if not result_id:
        flash('Invalid result ID.', 'danger')
        return redirect(url_for('user_dashboard'))
    
    conn = get_db_connection()
    if conn is None:
        flash('Database connection error.', 'danger')
        return redirect(url_for('user_dashboard'))
    
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute('''SELECT * FROM results 
            WHERE id = %s AND user_id = %s''',
            (result_id, session['user_id']))
        result = cursor.fetchone()
        
        if not result:
            flash('Result not found or you do not have permission to view it.', 'danger')
            return redirect(url_for('user_dashboard'))
        
        total = max(1, result['total_questions'])
        answers = json.loads(result['answers']) if result['answers'] else {}
        detailed_results = []
        
        for qid, user_answer in answers.items():
            cursor.execute('SELECT * FROM questions WHERE id = %s', (int(qid),))
            q = cursor.fetchone()
            
            if q:
                cursor.execute('''SELECT * FROM question_reviews 
                    WHERE question_id = %s AND user_id = %s''',
                    (q['id'], session['user_id']))
                existing_review = cursor.fetchone()
                
                detailed_results.append({
                    'question': q['question'],
                    'options': {'a': q['option_a'], 'b': q['option_b'], 'c': q['option_c'], 'd': q['option_d']},
                    'correct_answer': q['correct_answer'],
                    'user_answer': user_answer,
                    'explanation': q['explanation'],
                    'question_id': q['id'],
                    'already_reviewed': bool(existing_review),
                    'review': existing_review
                })
        
    except mysql.connector.Error as err:
        logger.error(f"Database error in results: {str(err)}")
        flash('Error retrieving result data.', 'danger')
        return redirect(url_for('user_dashboard'))
    finally:
        cursor.close()
        conn.close()
    
    return render_template('results.html',
                          score=result['score'],
                          total=total,
                          time=result['time_taken'],
                          detailed_results=detailed_results,
                          result_id=result_id,
                          date_taken=result['date_taken'])

@app.route('/review_question/<int:qid>', methods=['POST'])
@login_required
def review_question(qid):
    comment = sanitize_input(request.form.get('comment', ''))
    rating = request.form.get('rating', type=int)
    
    if not rating or not (1 <= rating <= 5):
        flash('Rating must be between 1 and 5.', 'danger')
        return redirect(request.referrer or url_for('user_dashboard'))
    
    conn = get_db_connection()
    if conn is None:
        flash('Database connection error.', 'danger')
        return redirect(request.referrer or url_for('user_dashboard'))
    
    cursor = conn.cursor()
    
    try:
        cursor.execute('SELECT id FROM questions WHERE id = %s', (qid,))
        if not cursor.fetchone():
            flash('Question not found.', 'danger')
            return redirect(request.referrer or url_for('user_dashboard'))
        
        cursor.execute('''SELECT id FROM question_reviews 
            WHERE question_id = %s AND user_id = %s''',
            (qid, session['user_id']))
        existing_review = cursor.fetchone()
        
        if existing_review:
            cursor.execute('''UPDATE question_reviews 
                SET comment = %s, rating = %s, created_at = %s
                WHERE question_id = %s AND user_id = %s''',
                (comment, rating, datetime.now(), qid, session['user_id']))
            flash('Your review has been updated.', 'success')
        else:
            cursor.execute('''INSERT INTO question_reviews 
                (question_id, user_id, comment, rating) 
                VALUES (%s, %s, %s, %s)''',
                (qid, session['user_id'], comment, rating))
            flash('Your review has been submitted.', 'success')
        
        conn.commit()
        
        socketio.emit('new_review', {
            'username': session['username'],
            'question_id': qid,
            'rating': rating
        }, namespace='/admin')
        
        logger.info(f"Question {qid} reviewed by user {session['username']}")
        
    except mysql.connector.Error as err:
        conn.rollback()
        logger.error(f"Database error during question review: {str(err)}")
        flash('Error submitting review.', 'danger')
    finally:
        cursor.close()
        conn.close()
    
    return redirect(request.referrer or url_for('user_dashboard'))

@app.route('/manage_questions', methods=['GET', 'POST'])
@super_admin_required
def manage_questions():
    conn = get_db_connection()
    if conn is None:
        flash('Database connection error.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    cursor = conn.cursor(dictionary=True)
    
    try:
        if request.method == 'POST' and 'question' in request.form:
            form = QuestionForm(request.form)
            
            if form.validate():
                question = sanitize_input(form.question.data)
                option_a = sanitize_input(form.option_a.data)
                option_b = sanitize_input(form.option_b.data)
                option_c = sanitize_input(form.option_c.data)
                option_d = sanitize_input(form.option_d.data)
                correct_answer = form.correct_answer.data
                category = sanitize_input(form.category.data)
                difficulty = form.difficulty.data
                exam_name = sanitize_input(form.exam_name.data)
                subject = sanitize_input(form.subject.data)
                topics = sanitize_input(form.topics.data)
                year = form.year.data
                explanation = sanitize_input(form.explanation.data)
                
                cursor.execute('''INSERT INTO questions 
                    (question, option_a, option_b, option_c, option_d, correct_answer, 
                     category, difficulty, exam_name, subject, topics, year, explanation, created_by) 
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)''',
                    (question, option_a, option_b, option_c, option_d, correct_answer,
                     category, difficulty, exam_name, subject, topics, year, explanation, session['user_id']))
                conn.commit()
                
                socketio.emit('new_question', {
                    'question': question[:50] + '...' if len(question) > 50 else question
                }, namespace='/admin')
                
                flash('Question added successfully.', 'success')
                logger.info(f"New question added by super_admin {session['username']}")
            else:
                for field, errors in form.errors.items():
                    for error in errors:
                        flash(f"Error in {field}: {error}", 'danger')
        
        filters = {}
        if request.method == 'POST' and 'filter' in request.form:
            filters = {
                'exam_name': sanitize_input(request.form.get('exam_name', '')),
                'year': sanitize_input(request.form.get('year', '')),
                'subject': sanitize_input(request.form.get('subject', '')),
                'topics': sanitize_input(request.form.get('topics', ''))
            }
            
            query = 'SELECT q.*, u.username FROM questions q LEFT JOIN users u ON q.created_by = u.id WHERE 1=1'
            params = []
            
            if filters.get('exam_name'):
                query += ' AND q.exam_name = %s'
                params.append(filters['exam_name'])
            if filters.get('year') and filters['year'].isdigit():
                query += ' AND q.year = %s'
                params.append(int(filters['year']))
            if filters.get('subject'):
                query += ' AND q.subject = %s'
                params.append(filters['subject'])
            if filters.get('topics'):
                topics = [t.strip() for t in filters['topics'].split(',')]
                placeholders = ', '.join(['%s'] * len(topics))
                query += f" AND (q.topics REGEXP CONCAT('(^|,)\\\\s*(', REPLACE(CONCAT({placeholders}), ',', '|'), ')\\\\s*(,|$)'))"
                params.extend(topics)
            
            query += ' ORDER BY q.id DESC'
            cursor.execute(query, params)
        else:
            cursor.execute('''SELECT q.*, u.username 
                FROM questions q 
                LEFT JOIN users u ON q.created_by = u.id 
                ORDER BY q.id DESC 
                LIMIT 100''')
        
        questions = cursor.fetchall()
        
        cursor.execute('SELECT DISTINCT exam_name FROM questions')
        exam_names = [row['exam_name'] for row in cursor.fetchall()]
        cursor.execute('SELECT DISTINCT year FROM questions ORDER BY year DESC')
        years = [row['year'] for row in cursor.fetchall()]
        cursor.execute('SELECT DISTINCT subject FROM questions')
        subjects = [row['subject'] for row in cursor.fetchall()]
        
    except mysql.connector.Error as err:
        logger.error(f"Database error in manage_questions: {str(err)}")
        flash('Error processing question data.', 'danger')
        questions = []
        exam_names = []
        years = []
        subjects = []
    finally:
        cursor.close()
        conn.close()
    
    return render_template('admin_questions.html', 
                          questions=questions,
                          exam_names=exam_names,
                          years=years,
                          subjects=subjects,
                          filters=filters)

@app.route('/edit_question/<int:question_id>', methods=['GET', 'POST'])
@super_admin_required
def edit_question(question_id):
    form = QuestionForm()
    
    conn = get_db_connection()
    if conn is None:
        flash('Database connection error.', 'danger')
        return redirect(url_for('manage_questions'))
    
    cursor = conn.cursor(dictionary=True)
    
    try:
        if request.method == 'GET':
            cursor.execute('SELECT * FROM questions WHERE id = %s', (question_id,))
            question = cursor.fetchone()
            
            if not question:
                flash('Question not found.', 'danger')
                return redirect(url_for('manage_questions'))
            
            form.question.data = question['question']
            form.option_a.data = question['option_a']
            form.option_b.data = question['option_b']
            form.option_c.data = question['option_c']
            form.option_d.data = question['option_d']
            form.correct_answer.data = question['correct_answer']
            form.category.data = question['category']
            form.difficulty.data = question['difficulty']
            form.exam_name.data = question['exam_name']
            form.subject.data = question['subject']
            form.topics.data = question['topics']
            form.year.data = question['year']
            form.explanation.data = question['explanation']
        
        elif form.validate_on_submit():
            cursor.execute('''UPDATE questions
                SET question = %s, option_a = %s, option_b = %s, option_c = %s, option_d = %s,
                    correct_answer = %s, category = %s, difficulty = %s, exam_name = %s,
                    subject = %s, topics = %s, year = %s, explanation = %s
                WHERE id = %s''',
                (sanitize_input(form.question.data), sanitize_input(form.option_a.data), sanitize_input(form.option_b.data),
                 sanitize_input(form.option_c.data), sanitize_input(form.option_d.data), form.correct_answer.data,
                 sanitize_input(form.category.data), form.difficulty.data, sanitize_input(form.exam_name.data),
                 sanitize_input(form.subject.data), sanitize_input(form.topics.data), form.year.data,
                 sanitize_input(form.explanation.data), question_id))
            conn.commit()
            
            flash('Question updated successfully.', 'success')
            logger.info(f"Question {question_id} updated by super_admin {session['username']}")
            return redirect(url_for('manage_questions'))
        
    except mysql.connector.Error as err:
        if request.method == 'POST':
            conn.rollback()
        logger.error(f"Database error during question edit: {str(err)}")
        flash('Error processing question data.', 'danger')
    finally:
        cursor.close()
        conn.close()
    
    return render_template('edit_question.html', form=form)

@app.route('/delete_question/<int:qid>', methods=['POST'])
@super_admin_required
def delete_question(qid):
    conn = get_db_connection()
    if conn is None:
        flash('Database connection error.', 'danger')
        return redirect(url_for('manage_questions'))
    
    cursor = conn.cursor()
    
    try:
        cursor.execute('SELECT id FROM questions WHERE id = %s', (qid,))
        if not cursor.fetchone():
            flash('Question not found.', 'danger')
        else:
            cursor.execute('DELETE FROM questions WHERE id = %s', (qid,))
            conn.commit()
            flash('Question deleted successfully.', 'success')
            logger.info(f"Question {qid} deleted by super_admin {session['username']}")
    except mysql.connector.Error as err:
        conn.rollback()
        logger.error(f"Database error during question deletion: {str(err)}")
        flash('Error deleting question.', 'danger')
    finally:
        cursor.close()
        conn.close()
    
    return redirect(url_for('manage_questions'))

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@super_admin_required
def edit_user(user_id):
    form = UserForm()
    
    conn = get_db_connection()
    if conn is None:
        flash('Database connection error.', 'danger')
        return redirect(url_for('manage_users'))
    
    cursor = conn.cursor(dictionary=True)
    
    try:
        if request.method == 'GET':
            cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
            user = cursor.fetchone()
            
            if not user:
                flash('User not found.', 'danger')
                return redirect(url_for('manage_users'))
            
            if user['id'] == session.get('user_id') and user['role'] == 'super_admin':
                flash("You cannot modify your own super admin privileges.", "warning")
            
            form.username.data = user['username']
            form.role.data = user['role']
            form.status.data = user['status']
        
        elif form.validate_on_submit():
            if user_id == 0:
                username = sanitize_input(form.username.data)
                role = form.role.data
                status = form.status.data
                password = form.password.data
                
                if not password:
                    flash('Password is required for new users.', 'danger')
                    return redirect(url_for('manage_users'))
                
                cursor.execute('SELECT id FROM users WHERE username = %s', (username,))
                if cursor.fetchone():
                    flash('Username already exists.', 'danger')
                    return redirect(url_for('manage_users'))
                
                hashed_password = generate_password_hash(password)
                cursor.execute('''INSERT INTO users (username, password, role, status, last_active) 
                    VALUES (%s, %s, %s, %s, %s)''',
                    (username, hashed_password, role, status, datetime.now()))
                conn.commit()
                
                flash('User created successfully.', 'success')
                return redirect(url_for('manage_users'))
            
            cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
            current_user = cursor.fetchone()
            
            if not current_user:
                flash('User not found.', 'danger')
                return redirect(url_for('manage_users'))
            
            if current_user['id'] == session.get('user_id') and current_user['role'] == 'super_admin' and form.role.data != 'super_admin':
                flash("You cannot remove your own super admin privileges.", "danger")
                return redirect(url_for('edit_user', user_id=user_id))
            
            username = sanitize_input(form.username.data)
            role = form.role.data
            status = form.status.data
            new_password = form.password.data
            
            if username != current_user['username']:
                cursor.execute('SELECT id FROM users WHERE username = %s AND id != %s', (username, user_id))
                if cursor.fetchone():
                    flash('Username already exists.', 'danger')
                    return redirect(url_for('edit_user', user_id=user_id))
            
            if new_password:
                hashed_password = generate_password_hash(new_password)
                cursor.execute('''UPDATE users 
                    SET username = %s, role = %s, status = %s, password = %s 
                    WHERE id = %s''',
                    (username, role, status, hashed_password, user_id))
            else:
                cursor.execute('''UPDATE users 
                    SET username = %s, role = %s, status = %s 
                    WHERE id = %s''',
                    (username, role, status, user_id))
            
            conn.commit()
            flash('User updated successfully.', 'success')
            logger.info(f"User {user_id} updated by super_admin {session['username']}")
            return redirect(url_for('manage_users'))
    
    except mysql.connector.Error as err:
        if request.method == 'POST':
            conn.rollback()
        logger.error(f"Database error during user edit: {str(err)}")
        flash('Error processing user data.', 'danger')
    finally:
        cursor.close()
        conn.close()
    
    return render_template('edit_user.html', form=form, user_id=user_id)

@app.route('/edit_student', methods=['POST'])
@institute_admin_required
def edit_student():
    student_id = request.form.get('student_id', type=int)
    username = sanitize_input(request.form.get('username'))
    email = sanitize_input(request.form.get('email'))
    status = sanitize_input(request.form.get('status'))
    password = request.form.get('password')
    
    if not student_id:
        flash('Student ID is required.', 'danger')
        return redirect(url_for('institution_dashboard'))
    
    institution_id = session.get('institution_id')
    
    conn = get_db_connection()
    if conn is None:
        flash('Database connection error.', 'danger')
        return redirect(url_for('institution_dashboard'))
        
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Verify student belongs to this institution
        cursor.execute('''SELECT * FROM users 
            WHERE id = %s AND institution_id = %s AND user_type = "institution_student"''',
            (student_id, institution_id))
        student = cursor.fetchone()
        
        if not student:
            flash('Student not found or does not belong to your institution.', 'danger')
            return redirect(url_for('institution_dashboard'))
        
        # Check if username already exists (excluding current student)
        if username != student['username']:
            cursor.execute('SELECT id FROM users WHERE username = %s AND id != %s', (username, student_id))
            if cursor.fetchone():
                flash('Username already exists. Please choose a different one.', 'danger')
                return redirect(url_for('institution_dashboard'))
        
        # Update student information
        if password:
            # Update with new password
            hashed_password = generate_password_hash(password)
            cursor.execute('''UPDATE users 
                SET username = %s, email = %s, status = %s, password = %s, last_active = %s
                WHERE id = %s''',
                (username, email, status, hashed_password, datetime.now(), student_id))
        else:
            # Update without changing password
            cursor.execute('''UPDATE users 
                SET username = %s, email = %s, status = %s, last_active = %s
                WHERE id = %s''',
                (username, email, status, datetime.now(), student_id))
        
        conn.commit()
        flash(f'Student {username} updated successfully.', 'success')
        logger.info(f"Student {student_id} updated by institute_admin {session['username']}")
        
    except mysql.connector.Error as err:
        conn.rollback()
        logger.error(f"Database error updating student: {str(err)}")
        flash('Error updating student information.', 'danger')
    finally:
        cursor.close()
        conn.close()
    
    return redirect(url_for('institution_dashboard'))

@app.route('/manage_users')
@super_admin_required
def manage_users():
    user_type = request.args.get('type', 'all')
    parent_id = request.args.get('parent_id', None)
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        if user_type == 'all':
            cursor.execute('''SELECT role, COUNT(*) as count, DATE_FORMAT(MAX(last_active), '%Y-%m-%d %H:%i') as last_active
                FROM users
                GROUP BY role
                ORDER BY FIELD(role, 'super_admin', 'institute_admin', 'individual_user', 'student_user')''')
            users = cursor.fetchall()
            return render_template('manage_users.html', 
                                   users=users, 
                                   view_type="summary",
                                   current_type="all")
        
        elif user_type == 'institute_admin':
            if parent_id:
                cursor.execute('''SELECT u.*, 
                           COUNT(DISTINCT r.id) as quiz_count,
                           AVG(r.score / r.total_questions * 100) as avg_score
                    FROM users u
                    LEFT JOIN results r ON u.id = r.user_id
                    WHERE u.role = 'student_user' AND u.institution_id = %s
                    GROUP BY u.id
                    ORDER BY u.username''', (parent_id,))
                users = cursor.fetchall()
                
                cursor.execute('SELECT name FROM institutions WHERE id = %s', (parent_id,))
                institution = cursor.fetchone()
                institution_name = institution['name'] if institution else "Unknown Institution"
                
                for user in users:
                    user['avg_score'] = round(user['avg_score'], 1) if user['avg_score'] else 0
                    if user['last_active']:
                        user['last_active_str'] = format_last_active(user['last_active'])
                    else:
                        user['last_active_str'] = "Never"
                
                cursor.execute('SELECT username FROM users WHERE id = %s', (parent_id,))
                admin = cursor.fetchone()
                admin_name = admin['username'] if admin else "Unknown Admin"
                
                return render_template('manage_users.html', 
                                    users=users, 
                                    view_type="students",
                                    current_type="student_user",
                                    institution_name=institution_name,
                                    admin_name=admin_name,
                                    parent_id=parent_id)
            else:
                cursor.execute('''SELECT u.*, i.name as institution_name,
                           COUNT(s.id) as student_count
                    FROM users u
                    LEFT JOIN institutions i ON u.institution_id = i.id
                    LEFT JOIN users s ON s.institution_id = i.id AND s.role = 'student_user'
                    WHERE u.role = 'institute_admin'
                    GROUP BY u.id
                    ORDER BY u.username''')
                users = cursor.fetchall()
                
                for user in users:
                    if user['last_active']:
                        user['last_active_str'] = format_last_active(user['last_active'])
                    else:
                        user['last_active_str'] = "Never"
                
                return render_template('manage_users.html', 
                                    users=users, 
                                    view_type="institute_admins",
                                    current_type="institute_admin")
        
        elif user_type in ['individual_user', 'student_user', 'super_admin']:
            cursor.execute('''SELECT u.*, 
                       COUNT(DISTINCT r.id) as quiz_count,
                       AVG(r.score / r.total_questions * 100) as avg_score,
                       i.name as institution_name
                FROM users u
                LEFT JOIN results r ON u.id = r.user_id
                LEFT JOIN institutions i ON u.institution_id = i.id
                WHERE u.role = %s
                GROUP BY u.id
                ORDER BY u.username''', (user_type,))
            users = cursor.fetchall()
            
            for user in users:
                user['avg_score'] = round(user['avg_score'], 1) if user['avg_score'] else 0
                if user['last_active']:
                    user['last_active_str'] = format_last_active(user['last_active'])
                else:
                    user['last_active_str'] = "Never"
            
            return render_template('manage_users.html', 
                                users=users, 
                                view_type="users",
                                current_type=user_type)
    
    except mysql.connector.Error as err:
        logger.error(f"Database error in manage_users: {str(err)}")
        flash('Error retrieving user data.', 'danger')
        return redirect(url_for('admin_dashboard'))
    finally:
        cursor.close()
        conn.close()

def format_last_active(last_active):
    now = datetime.now()
    diff = now - last_active
    if diff.days > 0:
        return f"{diff.days} days ago"
    elif diff.seconds >= 3600:
        return f"{diff.seconds // 3600} hours ago"
    elif diff.seconds >= 60:
        return f"{diff.seconds // 60} minutes ago"
    else:
        return "Just now"

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@super_admin_required
def delete_user(user_id):
    if user_id == session['user_id']:
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('manage_users'))
    
    conn = get_db_connection()
    if conn is None:
        flash('Database connection error.', 'danger')
        return redirect(url_for('manage_users'))
    
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute('SELECT role FROM users WHERE id = %s', (user_id,))
        user = cursor.fetchone()
        
        if not user:
            flash('User not found.', 'danger')
            return redirect(url_for('manage_users'))
        
        if user['role'] == 'super_admin':
            cursor.execute('SELECT COUNT(*) as count FROM users WHERE role = "super_admin"')
            admin_count = cursor.fetchone()['count']
            
            if admin_count <= 1:
                flash('Cannot delete the last super admin user.', 'danger')
                return redirect(url_for('manage_users'))
        
        cursor.execute('DELETE FROM users WHERE id = %s', (user_id,))
        conn.commit()
        
        flash('User and all associated data deleted successfully.', 'success')
        logger.info(f"User {user_id} deleted by super_admin {session['username']}")
    
    except mysql.connector.Error as err:
        conn.rollback()
        logger.error(f"Database error during user deletion: {str(err)}")
        flash('Error deleting user.', 'danger')
    finally:
        cursor.close()
        conn.close()
    
    return redirect(url_for('manage_users'))

@app.route('/subscriptions')
@login_required
def subscriptions():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute('''SELECT u.subscription_plan_id, u.subscription_start, u.subscription_end, p.name as plan_name
            FROM users u
            LEFT JOIN subscription_plans p ON u.subscription_plan_id = p.id
            WHERE u.id = %s''', (session['user_id'],))
        user_subscription = cursor.fetchone()
        
        cursor.execute('SELECT * FROM subscription_plans WHERE is_institution = FALSE ORDER BY price')
        plans = cursor.fetchall()
        
        for plan in plans:
            cursor.execute('SELECT exam_name FROM plan_exam_access WHERE plan_id = %s', (plan['id'],))
            plan['exams'] = [row['exam_name'] for row in cursor.fetchall()]
            
            if user_subscription and user_subscription['subscription_plan_id'] == plan['id']:
                plan['is_active'] = True
                plan['expires_on'] = user_subscription['subscription_end']
            else:
                plan['is_active'] = False
                plan['expires_on'] = None
        
        is_subscribed = user_subscription and user_subscription['subscription_end'] and user_subscription['subscription_end'] > datetime.now()
        
        return render_template('subscriptions.html', 
                              plans=plans, 
                              user_subscription=user_subscription,
                              is_subscribed=is_subscribed)
    except mysql.connector.Error as err:
        logger.error(f"Database error in subscriptions page: {str(err)}")
        flash('Error loading subscription data.', 'danger')
        return redirect(url_for('user_dashboard'))
    finally:
        cursor.close()
        conn.close()

@app.route('/subscribe/<int:plan_id>', methods=['GET', 'POST'])
@login_required
def subscribe(plan_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute('SELECT * FROM subscription_plans WHERE id = %s AND is_institution = FALSE', (plan_id,))
        plan = cursor.fetchone()
        
        if not plan:
            flash('Invalid subscription plan.', 'danger')
            return redirect(url_for('subscriptions'))
            
        form = SubscriptionForm()
        form.plan_id.choices = [(plan['id'], plan['name'])]
        
        cursor.execute('SELECT exam_name FROM plan_exam_access WHERE plan_id = %s', (plan_id,))
        plan['exams'] = [row['exam_name'] for row in cursor.fetchall()]
        
        if form.validate_on_submit():
            start_date = datetime.now()
            end_date = start_date + timedelta(days=plan['duration_days'])
            
            cursor.execute('''UPDATE users 
                SET subscription_plan_id = %s,
                    subscription_start = %s,
                    subscription_end = %s,
                    last_active = %s
                WHERE id = %s''', (plan_id, start_date, end_date, datetime.now(), session['user_id']))
            
            cursor.execute('''INSERT INTO subscription_history 
                (user_id, subscription_plan_id, start_date, end_date, amount_paid, payment_method) 
                VALUES (%s, %s, %s, %s, %s, %s)''', (session['user_id'], plan_id, start_date, end_date, plan['price'], form.payment_method.data))
            
            conn.commit()
            flash(f'You have successfully subscribed to {plan["name"]}!', 'success')
            return redirect(url_for('subscriptions'))
        
        return render_template('subscribe.html', form=form, plan=plan)
    except mysql.connector.Error as err:
        conn.rollback()
        logger.error(f"Database error during subscription: {str(err)}")
        flash('Error processing subscription.', 'danger')
        return redirect(url_for('subscriptions'))
    finally:
        cursor.close()
        conn.close()

@app.route('/subscription_history')
@login_required
def subscription_history():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute('''SELECT u.subscription_plan_id, u.subscription_start, u.subscription_end, 
                   p.name as plan_name, p.price
            FROM users u
            JOIN subscription_plans p ON u.subscription_plan_id = p.id
            WHERE u.id = %s AND u.subscription_end > NOW() 
                AND u.subscription_plan_id IS NOT NULL''', (session['user_id'],))
        active_sub = cursor.fetchone()
        
        if active_sub:
            cursor.execute('''SELECT COUNT(*) as count FROM subscription_history
                WHERE user_id = %s 
                AND subscription_plan_id = %s
                AND start_date = %s''', (session['user_id'], active_sub['subscription_plan_id'], active_sub['subscription_start']))
            
            history_exists = cursor.fetchone()['count'] > 0
            
            if not history_exists:
                cursor.execute('''INSERT INTO subscription_history 
                    (user_id, subscription_plan_id, start_date, end_date, amount_paid, payment_method) 
                    VALUES (%s, %s, %s, %s, %s, %s)''', (
                    session['user_id'], 
                    active_sub['subscription_plan_id'], 
                    active_sub['subscription_start'], 
                    active_sub['subscription_end'], 
                    active_sub['price'], 
                    'credit_card'
                ))
                conn.commit()
        
        cursor.execute('''SELECT sh.id, sh.start_date, sh.end_date, sh.amount_paid, sh.payment_method,
                   p.name as plan_name, p.description
            FROM subscription_history sh
            JOIN subscription_plans p ON sh.subscription_plan_id = p.id
            WHERE sh.user_id = %s
            ORDER BY sh.start_date DESC''', (session['user_id'],))
        history = cursor.fetchall()
        
        current_time = datetime.now()
        
        return render_template('subscription_history.html', history=history, now=current_time)
    except mysql.connector.Error as err:
        logger.error(f"Database error in subscription history: {str(err)}")
        flash('Error retrieving subscription history.', 'danger')
        return redirect(url_for('user_dashboard'))
    finally:
        cursor.close()
        conn.close()

@app.route('/quiz', methods=['GET', 'POST'])
@quiz_access_required
def quiz():
    conn = get_db_connection()
    if conn is None:
        flash('Database connection error.', 'danger')
        return redirect(url_for('user_dashboard'))
        
    cursor = conn.cursor(dictionary=True)
    
    try:
        user_role = session.get('role')
        user_id = session.get('user_id')
        is_admin = user_role in ['super_admin', 'institute_admin']
        is_institution_student = user_role == 'student_user'
        
        logger.debug(f"User ID: {user_id}, Role: {user_role}, Session: {session}")
        
        # Initialize filters to empty dict if not exists
        filters = {}
        questions = []
        quiz_type = request.form.get('quiz_type', 'previous_year')
        
        accessible_exams = []
        if user_role == 'individual_user':
            cursor.execute('''SELECT subscription_plan_id, subscription_end
                              FROM users WHERE id = %s''', (user_id,))
            user_subscription = cursor.fetchone()
            
            if user_subscription and user_subscription['subscription_end'] and user_subscription['subscription_end'] > datetime.now():
                cursor.execute('SELECT exam_name FROM plan_exam_access WHERE plan_id = %s', (user_subscription['subscription_plan_id'],))
                accessible_exams = [row['exam_name'] for row in cursor.fetchall()]
            else:
                flash('You need an active subscription to access quizzes.', 'warning')
                return redirect(url_for('subscriptions'))
        else:
            # Admins and students have access to all exams
            cursor.execute('SELECT DISTINCT exam_name FROM questions')
            accessible_exams = [row['exam_name'] for row in cursor.fetchall()]

        if request.method == 'POST':
            if 'filter' in request.form:
                # This is a filter request, just update filters
                exam_name = sanitize_input(request.form.get('exam_name', ''))
                year = sanitize_input(request.form.get('year', ''))
                subject = sanitize_input(request.form.get('subject', ''))
                topics = sanitize_input(request.form.get('topics', ''))
                difficulty = sanitize_input(request.form.get('difficulty', ''))
                
                filters = {
                    'exam_name': exam_name,
                    'year': year,
                    'subject': subject,
                    'topics': topics,
                    'difficulty': difficulty
                }
                
                # Return the page with filters applied but no questions yet
                
            elif 'generate' in request.form:
                # This is a quiz generation request
                exam_name = sanitize_input(request.form.get('exam_name', ''))
                year = sanitize_input(request.form.get('year', ''))
                subject = sanitize_input(request.form.get('subject', ''))
                topics = sanitize_input(request.form.get('topics', ''))
                difficulty = sanitize_input(request.form.get('difficulty', 'medium'))
                num_questions = 10  # Default value, could be made configurable
                
                # Update filters for template
                filters = {
                    'exam_name': exam_name,
                    'year': year,
                    'subject': subject,
                    'topics': topics,
                    'difficulty': difficulty
                }
                
                # Build the query based on filters
                query_parts = ['SELECT * FROM questions WHERE 1=1']
                query_params = []
                
                if quiz_type == 'previous_year':
                    if exam_name and exam_name in accessible_exams:
                        query_parts.append('AND exam_name = %s')
                        query_params.append(exam_name)
                    elif not is_admin and not is_institution_student:
                        # For individual users, restrict to accessible exams
                        if accessible_exams:
                            placeholder = ', '.join(['%s'] * len(accessible_exams))
                            query_parts.append(f'AND exam_name IN ({placeholder})')
                            query_params.extend(accessible_exams)
                        else:
                            flash('No exam access with your current subscription.', 'warning')
                            return redirect(url_for('subscriptions'))
                    
                    if year:
                        query_parts.append('AND year = %s')
                        query_params.append(int(year))
                else:  # subject_wise
                    if subject:
                        query_parts.append('AND subject = %s')
                        query_params.append(subject)
                    
                    if topics:
                        # Split topics by comma and search
                        topic_list = [t.strip() for t in topics.split(',')]
                        topic_conditions = []
                        for topic in topic_list:
                            topic_conditions.append('topics LIKE %s')
                            query_params.append(f'%{topic}%')
                        
                        if topic_conditions:
                            query_parts.append(f"AND ({' OR '.join(topic_conditions)})")
                
                if difficulty:
                    query_parts.append('AND difficulty = %s')
                    query_params.append(difficulty)
                
                # Add access control for individual users
                if user_role == 'individual_user' and accessible_exams:
                    placeholder = ', '.join(['%s'] * len(accessible_exams))
                    query_parts.append(f'AND exam_name IN ({placeholder})')
                    query_params.extend(accessible_exams)
                
                # Complete the query
                query_parts.append('ORDER BY RAND()')
                query_parts.append('LIMIT %s')
                query_params.append(num_questions)
                
                final_query = ' '.join(query_parts)
                logger.debug(f"Quiz query: {final_query} with params {query_params}")
                
                cursor.execute(final_query, query_params)
                questions = cursor.fetchall()
                
                if not questions:
                    flash('No questions found matching your criteria. Try different filters.', 'warning')
            
            # If there's an actual form submission for taking the quiz
            elif any(key.startswith('question_') for key in request.form.keys()):
                # This is an actual quiz submission
                session['quiz_questions'] = {}
                user_answers = {}
                
                for key, value in request.form.items():
                    if key.startswith('question_'):
                        question_id = key.replace('question_', '')
                        cursor.execute('SELECT * FROM questions WHERE id = %s', (question_id,))
                        q = cursor.fetchone()
                        
                        if q:
                            # Store answer for saving later
                            user_answers[question_id] = value
                            
                            # Store question info for the results page
                            session['quiz_questions'][question_id] = {
                                'question': q['question'],
                                'options': {
                                    'a': q['option_a'],
                                    'b': q['option_b'],
                                    'c': q['option_c'],
                                    'd': q['option_d']
                                },
                                'correct_answer': q['correct_answer'],
                                'explanation': q['explanation']
                            }
                
                if user_answers:
                    # Calculate score
                    score = 0
                    for qid, user_answer in user_answers.items():
                        correct_answer = session['quiz_questions'][qid]['correct_answer']
                        if user_answer == correct_answer:
                            score += 1
                    
                    time_taken = int(request.form.get('time_taken', 0))
                    
                    # Save results
                    cursor.execute('''INSERT INTO results 
                        (user_id, score, total_questions, time_taken, answers, date_taken) 
                        VALUES (%s, %s, %s, %s, %s, %s)''',
                        (session['user_id'], score, len(user_answers), time_taken, json.dumps(user_answers), datetime.now()))
                    conn.commit()
                    
                    result_id = cursor.lastrowid
                    
                    flash(f'Quiz completed! Your score: {score}/{len(user_answers)}', 'success')
                    logger.info(f"User {session['username']} completed quiz with score {score}/{len(user_answers)}")
                    return redirect(url_for('results', result_id=result_id))
                else:
                    flash('No answers submitted.', 'warning')
        
        # Get data for filter dropdowns
        cursor.execute('SELECT DISTINCT exam_name FROM questions')
        exam_names = [row['exam_name'] for row in cursor.fetchall()]
        
        cursor.execute('SELECT DISTINCT year FROM questions ORDER BY year DESC')
        years = [row['year'] for row in cursor.fetchall()]
        
        cursor.execute('SELECT DISTINCT subject FROM questions')
        subjects = [row['subject'] for row in cursor.fetchall()]
        
        return render_template('quiz.html', 
                              exam_names=exam_names,
                              years=years,
                              subjects=subjects,
                              accessible_exams=accessible_exams,
                              filters=filters,  # Always pass filters, even if empty
                              questions=questions,
                              quiz_type=quiz_type,
                              difficulties=['easy', 'medium', 'hard'])
    
    except mysql.connector.Error as err:
        logger.error(f"Database error in quiz: {str(err)}")
        flash('Error loading quiz data.', 'danger')
        return redirect(url_for('user_dashboard'))
    finally:
        cursor.close()
        conn.close()

@app.route('/take_quiz', methods=['GET', 'POST'])
@quiz_access_required
def take_quiz():
    if 'quiz_questions' not in session:
        flash('No quiz in progress. Please start a new quiz.', 'warning')
        return redirect(url_for('quiz'))
    
    questions = session['quiz_questions']
    
    if request.method == 'POST':
        user_answers = {qid: sanitize_input(request.form.get(qid)) for qid in questions.keys()}
        score = 0
        total_questions = len(questions)
        
        for qid, user_answer in user_answers.items():
            if user_answer == questions[qid]['correct_answer']:
                score += 1
        
        start_time = datetime.fromisoformat(session['quiz_start_time'])
        time_taken = int((datetime.now() - start_time).total_seconds())
        
        conn = get_db_connection()
        if conn is None:
            flash('Database connection error.', 'danger')
            return redirect(url_for('user_dashboard'))
        
        cursor = conn.cursor()
        
        try:
            cursor.execute('''INSERT INTO results 
                (user_id, score, total_questions, time_taken, answers, date_taken) 
                VALUES (%s, %s, %s, %s, %s, %s)''',
                (session['user_id'], score, total_questions, time_taken, json.dumps(user_answers), datetime.now()))
            conn.commit()
            
            result_id = cursor.lastrowid
            session.pop('quiz_questions', None)
            session.pop('quiz_start_time', None)
            session.pop('quiz_exam_name', None)
            
            flash(f'Quiz completed! Your score: {score}/{total_questions}', 'success')
            logger.info(f"User {session['username']} completed quiz with score {score}/{total_questions}")
            return redirect(url_for('results', result_id=result_id))
        
        except mysql.connector.Error as err:
            conn.rollback()
            logger.error(f"Database error during quiz submission: {str(err)}")
            flash('Error saving quiz results.', 'danger')
        finally:
            cursor.close()
            conn.close()
    
    return render_template('take_quiz.html', questions=questions)

# SocketIO Events for Admin Dashboard
@socketio.on('connect', namespace='/admin')
def handle_connect():
    if session.get('role') in ['super_admin', 'institute_admin']:
        logger.debug(f"Admin {session['username']} connected to SocketIO")
    else:
        socketio.emit('disconnect', namespace='/admin')

@socketio.on('disconnect', namespace='/admin')
def handle_disconnect():
    logger.debug(f"Admin {session.get('username', 'Unknown')} disconnected from SocketIO")

# Error Handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    logger.error(f"Internal server error: {str(e)}")
    return render_template('500.html'), 500

@app.errorhandler(413)
def request_entity_too_large(e):
    flash('File too large. Maximum size is 16MB.', 'danger')
    return redirect(request.url), 413

# Run the Application
if __name__ == '__main__':
    init_db()
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)