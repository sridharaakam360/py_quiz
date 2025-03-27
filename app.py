from flask import Flask, render_template, request, redirect, url_for, flash, session, Response, jsonify
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SelectField, IntegerField, SubmitField, PasswordField, RadioField, BooleanField
from wtforms.validators import DataRequired, Length, ValidationError, Regexp, Email
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
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'my-static-secret-key-12345')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Setup logging
logging.basicConfig(
    level=logging.DEBUG,
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
    'database': 'exit_database',
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

# Redis configuration from environment variables
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')

# Initialize Flask-Limiter for production
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["500 per day", "100 per hour"],
    storage_uri=REDIS_URL,
    storage_options={"socket_connect_timeout": 5},
    enabled=not app.debug  # Disable in debug mode
)

# Security helpers
def sanitize_input(text):
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
        if 'username' not in session or session.get('role') != 'superadmin':
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
            
        if session.get('role') != 'instituteadmin':
            logger.warning(f"Access to {request.path} rejected - user {session.get('username')} is not an instituteadmin")
            flash('Institute admin privileges required.', 'danger')
            if session.get('role') in ['individual', 'student']:
                return redirect(url_for('user_dashboard'))
            return redirect(url_for('choose_login'))
            
        if not session.get('institution_id'):
            logger.error(f"instituteadmin missing institution_id: {session}")
            flash('Institution not found. Please log in again.', 'danger')
            session.clear()
            return redirect(url_for('choose_login'))
            
        return f(*args, **kwargs)
    return decorated_function

def quiz_access_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session or session.get('role') not in ['individual', 'student', 'instituteadmin', 'superadmin']:
            flash('Please log in to access quizzes.', 'danger')
            return redirect(url_for('choose_login'))
        return f(*args, **kwargs)
    return decorated_function

def any_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session or session.get('role') not in ['instituteadmin', 'superadmin']:
            flash('Admin privileges required.', 'danger')
            return redirect(url_for('choose_login'))
        return f(*args, **kwargs)
    return decorated_function

# Forms (already defined in your script)

class LoginTypeForm(FlaskForm):
    login_type = RadioField('Login Type', choices=[
        ('individual', 'Individual Login'), 
        ('institution', 'Institution Admin'), 
        ('student', 'Institution Student')
    ], validators=[DataRequired()])
    submit = SubmitField('Continue')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=50)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=50)])
    submit = SubmitField('Login')


class InstitutionLoginForm(FlaskForm):
    institution_code = StringField('Institution Code', validators=[DataRequired(), Length(min=6, max=20)])
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=50)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=50)])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=50)])
    email = StringField('Email', validators=[DataRequired(), Regexp(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', message='Invalid email address')])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=50)])
    submit = SubmitField('Register')

class InstitutionRegisterForm(FlaskForm):
    institution_name = StringField('Institution Name', validators=[DataRequired(), Length(min=2, max=100)])
    admin_name = StringField('Admin Name', validators=[DataRequired(), Length(min=2, max=100)])
    email = StringField('Email Address', validators=[DataRequired(), Regexp(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', message='Invalid email address')])
    username = StringField('Admin Username', validators=[DataRequired(), Length(min=4, max=50)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=50)])  # Aligned with previous forms
    subscription_plan = SelectField('Subscription Plan', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Register')

class StudentRegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=50)])
    email = StringField('Email', validators=[DataRequired(), Regexp(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', message='Invalid email address')])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=50)])
    institution_code = StringField('Institution Code', validators=[DataRequired(), Length(min=6, max=20)])
    submit = SubmitField('Register as Student')

class QuestionForm(FlaskForm):
    question = TextAreaField('Question', validators=[DataRequired(), Length(min=1, max=500)])
    option_a = StringField('Option A', validators=[DataRequired(), Length(min=1, max=200)])
    option_b = StringField('Option B', validators=[DataRequired(), Length(min=1, max=200)])
    option_c = StringField('Option C', validators=[DataRequired(), Length(min=1, max=200)])
    option_d = StringField('Option D', validators=[DataRequired(), Length(min=1, max=200)])
    correct_answer = SelectField('Correct Answer', choices=[('a', 'A'), ('b', 'B'), ('c', 'C'), ('d', 'D')], validators=[DataRequired()])
    category = StringField('Category', validators=[DataRequired(), Length(min=1, max=100)])
    difficulty = SelectField('Difficulty', choices=[('easy', 'Easy'), ('medium', 'Medium'), ('hard', 'Hard')], validators=[DataRequired()])
    subject_id = SelectField('Subject', coerce=int, validators=[DataRequired()])
    previous_year = IntegerField('Previous Year', validators=[])
    topics = StringField('Topics', validators=[DataRequired(), Length(min=1, max=200)])
    explanation = TextAreaField('Explanation', validators=[DataRequired(), Length(min=1, max=500)])
    is_previous_year = BooleanField('Mark as Previous Year Question')

class UserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=50)])
    email = StringField('Email', validators=[DataRequired(), Regexp(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', message='Invalid email address')])
    role = SelectField('Role', choices=[('individual', 'Individual User'), ('student', 'Student User'), ('instituteadmin', 'Institute Admin'), ('superadmin', 'Super Admin')], validators=[DataRequired()])
    user_type = SelectField('User Type', choices=[('individual', 'Individual'), ('institutional', 'Institutional')], validators=[DataRequired()])
    status = SelectField('Status', choices=[('active', 'Active'), ('inactive', 'Inactive'), ('suspended', 'Suspended')], validators=[DataRequired()])
    password = PasswordField('New Password (leave blank to keep unchanged)', validators=[Length(min=6, max=50, message='Password must be 6-50 characters if provided')])
    submit = SubmitField('Update User')


class AddStudentForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=50)])
    email = StringField('Email', validators=[DataRequired(), Regexp(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', message='Invalid email address')])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=50)])
    institution_code = StringField('Institution Code (optional if adding within institution)', validators=[Length(min=6, max=20)], default=None)
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
        cursor.execute("CREATE DATABASE IF NOT EXISTS exit_database")
        cursor.execute("USE exit_database")

        # Users table (already provided)
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            degree ENUM('Dpharm', 'Bpharm', 'none') DEFAULT 'none',
            role ENUM('individual', 'student', 'instituteadmin', 'superadmin') DEFAULT 'individual',
            user_type ENUM('individual', 'institutional') DEFAULT 'individual',
            status ENUM('active', 'inactive', 'suspended') DEFAULT 'active',
            institution_id INT,
            subscription_plan_id INT,
            subscription_start DATETIME,
            subscription_end DATETIME,
            subscription_status ENUM('active', 'expired', 'pending') DEFAULT 'pending',
            last_active DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_username (username),
            INDEX idx_role (role),
            INDEX idx_status (status),
            INDEX idx_last_active (last_active)
        )''')

        # Exams table (already provided)
        cursor.execute('''CREATE TABLE IF NOT EXISTS exams (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name ENUM('MRB', 'ELITE', 'RRB', 'SBI', 'ISRO', 'Gpat', 'Drug Inspector', 'Junior Analyst', 'DRDO') NOT NULL,
            degree_type ENUM('Dpharm', 'Bpharm') NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')

        # Subjects table (already provided)
        cursor.execute('''CREATE TABLE IF NOT EXISTS subjects (
            id INT AUTO_INCREMENT PRIMARY KEY,
            exam_id INT NOT NULL,
            name ENUM('Anatomy', 'Drug Store', 'Pharmacology(D)', 'Pharmaceutics(D)', 
                    'Medicinal Chemistry', 'Pharmaceutics(B)', 'Pharmacology(B)') NOT NULL,
            degree_type ENUM('Dpharm', 'Bpharm') NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (exam_id) REFERENCES exams(id) ON DELETE CASCADE
        )''')

        # Questions table (already provided)
        cursor.execute('''CREATE TABLE IF NOT EXISTS questions (
            id INT AUTO_INCREMENT PRIMARY KEY,
            question TEXT NOT NULL,
            option_a VARCHAR(255) NOT NULL,
            option_b VARCHAR(255) NOT NULL,
            option_c VARCHAR(255) NOT NULL,
            option_d VARCHAR(255) NOT NULL,
            correct_answer CHAR(1) NOT NULL,
            category VARCHAR(50) NOT NULL,
            difficulty ENUM('easy', 'medium', 'hard') DEFAULT 'medium',
            subject_id INT,
            is_previous_year BOOLEAN DEFAULT FALSE,
            previous_year INT,
            topics JSON,
            explanation TEXT NOT NULL,
            created_by INT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (subject_id) REFERENCES subjects(id) ON DELETE SET NULL,
            FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
        )''')

        # Subscription_plans table (already provided)
        cursor.execute('''CREATE TABLE IF NOT EXISTS subscription_plans (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name ENUM('Dpharm Package', 'Bpharm Package', 'Combo Package') NOT NULL,
            price DECIMAL(10,2) NOT NULL,
            duration_days INT NOT NULL,
            description TEXT,
            degree_access ENUM('Dpharm', 'Bpharm', 'both') NOT NULL,
            includes_previous_years BOOLEAN DEFAULT TRUE,
            is_institution BOOLEAN DEFAULT FALSE,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')

        # Plan_exam_access table (already provided)
        cursor.execute('''CREATE TABLE IF NOT EXISTS plan_exam_access (
            id INT AUTO_INCREMENT PRIMARY KEY,
            plan_id INT NOT NULL,
            exam_id INT NOT NULL,
            subject_id INT,
            FOREIGN KEY (plan_id) REFERENCES subscription_plans(id) ON DELETE CASCADE,
            FOREIGN KEY (exam_id) REFERENCES exams(id) ON DELETE CASCADE,
            FOREIGN KEY (subject_id) REFERENCES subjects(id) ON DELETE CASCADE,
            UNIQUE KEY unique_plan_exam_subject (plan_id, exam_id, subject_id)
        )''')

        # Results table (missing)
        cursor.execute('''CREATE TABLE IF NOT EXISTS results (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            exam_id INT,
            score INT NOT NULL,
            total_questions INT NOT NULL,
            time_taken INT NOT NULL,
            answers JSON,
            date_taken DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (exam_id) REFERENCES exams(id) ON DELETE SET NULL
        )''')

        # Question_reviews table (missing)
        cursor.execute('''CREATE TABLE IF NOT EXISTS question_reviews (
            id INT AUTO_INCREMENT PRIMARY KEY,
            question_id INT NOT NULL,
            user_id INT NOT NULL,
            comment TEXT,
            rating INT NOT NULL CHECK (rating >= 1 AND rating <= 5),
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (question_id) REFERENCES questions(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )''')

        # Subscription_history table (missing)
        cursor.execute('''CREATE TABLE IF NOT EXISTS subscription_history (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            subscription_plan_id INT NOT NULL,
            start_date DATETIME NOT NULL,
            end_date DATETIME NOT NULL,
            amount_paid DECIMAL(10,2) NOT NULL,
            payment_method VARCHAR(50) NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (subscription_plan_id) REFERENCES subscription_plans(id) ON DELETE CASCADE
        )''')

        # Institutions table (missing)
        cursor.execute('''CREATE TABLE IF NOT EXISTS institutions (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            admin_id INT,
            subscription_plan_id INT,
            subscription_start DATETIME,
            subscription_end DATETIME,
            institution_code VARCHAR(20) UNIQUE NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (admin_id) REFERENCES users(id) ON DELETE SET NULL,
            FOREIGN KEY (subscription_plan_id) REFERENCES subscription_plans(id) ON DELETE SET NULL
        )''')

        # Institution_students table (missing)
        cursor.execute('''CREATE TABLE IF NOT EXISTS institution_students (
            id INT AUTO_INCREMENT PRIMARY KEY,
            institution_id INT NOT NULL,
            user_id INT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (institution_id) REFERENCES institutions(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE KEY unique_student_institution (institution_id, user_id)
        )''')

        # Superadmin creation
        cursor.execute('SELECT COUNT(*) FROM users WHERE role = "superadmin"')
        if cursor.fetchone()[0] == 0:
            admin_password = os.getenv('ADMIN_PASSWORD', 'admin123')
            cursor.execute('''INSERT INTO users (
                username, 
                email, 
                password, 
                role, 
                status, 
                degree,
                subscription_status
            ) VALUES (%s, %s, %s, %s, %s, %s, %s)''',
            (
                'superadmin', 
                'admin@example.com', 
                generate_password_hash(admin_password), 
                'superadmin', 
                'active',
                'none',  # Added degree field, using 'none' as superadmin isn't Dpharm/Bpharm specific
                'active'  # Added subscription_status as it's NOT NULL with default 'pending'
            ))
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
    if 'username' in session:
        if session['role'] == 'superadmin':
            return redirect(url_for('admin_dashboard'))
        elif session['role'] == 'instituteadmin':
            return redirect(url_for('institution_dashboard'))
        elif session['role'] in ['individual', 'student']:
            return redirect(url_for('user_dashboard'))
    return redirect(url_for('choose_login'))

@app.route('/ping')
@limiter.limit("50 per hour")
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

@app.route('/quiz', methods=['GET', 'POST'])
@limiter.limit("50 per hour")
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
        
        # Pre-fetch accessible exams once
        accessible_exams = []
        if user_role == 'individual':
            cursor.execute('''SELECT subscription_plan_id, subscription_end, subscription_status
                            FROM users WHERE id = %s''', (user_id,))
            user_subscription = cursor.fetchone()
            if user_subscription and user_subscription['subscription_end'] > datetime.now() and user_subscription['subscription_status'] == 'active':
                cursor.execute('''SELECT e.id, e.name FROM plan_exam_access pea 
                                JOIN exams e ON pea.exam_id = e.id 
                                WHERE pea.plan_id = %s''', (user_subscription['subscription_plan_id'],))
                accessible_exams = [(row['id'], row['name']) for row in cursor.fetchall()]
            else:
                flash('You need an active subscription to access quizzes.', 'warning')
                return redirect(url_for('subscriptions'))
        else:
            cursor.execute('SELECT id, name FROM exams')
            accessible_exams = [(row['id'], row['name']) for row in cursor.fetchall()]

        if request.method == 'POST':
            quiz_type = request.form.get('quiz_type', 'previous_year')
            if 'generate' in request.form:
                exam_id = sanitize_input(request.form.get('exam_id', ''))
                subject_id = sanitize_input(request.form.get('subject_id', ''))
                difficulty = sanitize_input(request.form.get('difficulty', 'medium'))
                num_questions = min(int(request.form.get('num_questions', 10)), 50)  # Cap for performance

                query = '''SELECT q.*, s.name AS subject_name, s.exam_id 
                          FROM questions q JOIN subjects s ON q.subject_id = s.id 
                          WHERE 1=1'''
                params = []

                if quiz_type == 'previous_year' and exam_id:
                    query += ' AND s.exam_id = %s AND q.is_previous_year = TRUE'
                    params.append(int(exam_id))
                elif quiz_type == 'subject_wise' and subject_id:
                    query += ' AND q.subject_id = %s'
                    params.append(int(subject_id))
                if difficulty:
                    query += ' AND q.difficulty = %s'
                    params.append(difficulty)
                if user_role == 'individual' and accessible_exams:
                    exam_ids = [exam[0] for exam in accessible_exams]
                    query += f' AND s.exam_id IN ({",".join(["%s"] * len(exam_ids))})'
                    params.extend(exam_ids)
                
                query += ' ORDER BY RAND() LIMIT %s'
                params.append(num_questions)

                cursor.execute(query, params)
                questions = cursor.fetchall()

                if not questions:
                    flash('No questions found matching your criteria.', 'warning')

            elif any(key.startswith('question_') for key in request.form.keys()):
                conn.start_transaction()  # Explicit transaction for submission
                user_answers = {}
                exam_id = None
                for key, value in request.form.items():
                    if key.startswith('question_'):
                        question_id = int(key.replace('question_', ''))
                        user_answers[question_id] = value.upper()
                        if not exam_id:
                            cursor.execute('SELECT s.exam_id FROM questions q JOIN subjects s ON q.subject_id = s.id WHERE q.id = %s', (question_id,))
                            exam_id = cursor.fetchone()['exam_id']

                if user_answers:
                    # Batch check answers
                    question_ids = list(user_answers.keys())
                    cursor.execute(f'''SELECT id, correct_answer 
                                    FROM questions 
                                    WHERE id IN ({','.join(['%s'] * len(question_ids))})''', question_ids)
                    correct_answers = {row['id']: row['correct_answer'] for row in cursor.fetchall()}
                    
                    score = sum(1 for qid, ans in user_answers.items() if correct_answers.get(qid) == ans)
                    total_questions = len(user_answers)
                    time_taken = int(request.form.get('time_taken', 0))

                    cursor.execute('''INSERT INTO results 
                                    (user_id, exam_id, score, total_questions, time_taken, answers, date_taken) 
                                    VALUES (%s, %s, %s, %s, %s, %s, %s)''',
                                    (user_id, exam_id, score, total_questions, time_taken, json.dumps(user_answers), datetime.now()))
                    conn.commit()
                    flash(f'Quiz completed! Your score: {score}/{total_questions}', 'success')
                    return redirect(url_for('results', result_id=cursor.lastrowid))

        # Pre-fetch dropdown data
        cursor.execute('SELECT id, name FROM exams')
        exams = cursor.fetchall()
        cursor.execute('SELECT id, name FROM subjects')
        subjects = cursor.fetchall()

        return render_template('quiz.html', exams=exams, subjects=subjects, accessible_exams=accessible_exams, questions=questions or [])
    
    except mysql.connector.Error as err:
        conn.rollback()
        logger.error(f"Database error in quiz: {str(err)}")
        flash('Error processing quiz.', 'danger')
        return redirect(url_for('user_dashboard'))
    finally:
        cursor.close()
        conn.close()


@app.route('/results')
@login_required
@limiter.limit("50 per hour")
def results():
    result_id = request.args.get('result_id', type=int)
    if not result_id:
        flash('Result ID is required.', 'danger')
        return redirect(url_for('user_dashboard'))

    conn = get_db_connection()
    if conn is None:
        flash('Database connection error.', 'danger')
        return redirect(url_for('user_dashboard'))
    
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute('''SELECT r.*, e.name AS exam_name 
                         FROM results r LEFT JOIN exams e ON r.exam_id = e.id 
                         WHERE r.id = %s AND r.user_id = %s''', (result_id, session['user_id']))
        result = cursor.fetchone()
        if not result:
            flash('Result not found or access denied.', 'danger')
            return redirect(url_for('user_dashboard'))

        answers = json.loads(result['answers']) if result['answers'] else {}
        if not answers:
            return render_template('results.html', score=result['score'], total=result['total_questions'], time=result['time_taken'], detailed_results=[])

        # Batch fetch questions and reviews
        question_ids = list(answers.keys())
        cursor.execute(f'''SELECT q.*, s.name AS subject_name 
                         FROM questions q LEFT JOIN subjects s ON q.subject_id = s.id 
                         WHERE q.id IN ({','.join(['%s'] * len(question_ids))})''', question_ids)
        questions = {q['id']: q for q in cursor.fetchall()}

        cursor.execute(f'''SELECT question_id, comment, rating 
                         FROM question_reviews 
                         WHERE question_id IN ({','.join(['%s'] * len(question_ids))}) AND user_id = %s''', 
                         question_ids + [session['user_id']])
        reviews = {r['question_id']: r for r in cursor.fetchall()}

        detailed_results = [
            {
                'question': q['question'],
                'options': {'A': q['option_a'], 'B': q['option_b'], 'C': q['option_c'], 'D': q['option_d']},
                'correct_answer': q['correct_answer'],
                'user_answer': answers[str(q['id'])].upper(),
                'explanation': q['explanation'],
                'subject': q['subject_name'],
                'question_id': q['id'],
                'already_reviewed': q['id'] in reviews,
                'review': reviews.get(q['id'])
            } for qid, q in questions.items()
        ]

        return render_template('results.html', score=result['score'], total=result['total_questions'], time=result['time_taken'], detailed_results=detailed_results, exam_name=result['exam_name'], date_taken=result['date_taken'])
    
    except mysql.connector.Error as err:
        logger.error(f"Database error in results: {str(err)}")
        flash('Error retrieving results.', 'danger')
        return redirect(url_for('user_dashboard'))
    finally:
        cursor.close()
        conn.close()

@app.route('/review_question/<int:qid>', methods=['POST'])
@login_required
@limiter.limit("50 per hour")
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
@limiter.limit("50 per hour")
def manage_questions():
    conn = get_db_connection()
    if conn is None:
        flash('Database connection error.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    cursor = conn.cursor(dictionary=True)
    try:
        form = QuestionForm()
        cursor.execute('SELECT id, name FROM subjects ORDER BY name')
        subjects = cursor.fetchall()
        if not subjects:
            flash('No subjects available. Please add subjects first.', 'danger')
            return redirect(url_for('admin_dashboard'))
        form.subject_id.choices = [(s['id'], s['name']) for s in subjects]

        if request.method == 'POST' and 'question' in request.form and form.validate_on_submit():
            topics_json = json.dumps([t.strip() for t in form.topics.data.split(',')]) if form.topics.data else '[]'
            cursor.execute('''INSERT INTO questions 
                            (question, option_a, option_b, option_c, option_d, correct_answer, category, difficulty, subject_id, 
                            is_previous_year, previous_year, topics, explanation, created_by) 
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)''',
                            (sanitize_input(form.question.data), sanitize_input(form.option_a.data), sanitize_input(form.option_b.data),
                             sanitize_input(form.option_c.data), sanitize_input(form.option_d.data), form.correct_answer.data.upper(),
                             sanitize_input(form.category.data), form.difficulty.data, form.subject_id.data,
                             form.is_previous_year.data, form.previous_year.data if form.is_previous_year.data else None,
                             topics_json, sanitize_input(form.explanation.data), session['user_id']))
            conn.commit()
            flash('Question added successfully.', 'success')
            return redirect(url_for('manage_questions'))

        # Pagination for scalability
        page = request.args.get('page', 1, type=int)
        per_page = 20
        offset = (page - 1) * per_page
        cursor.execute('''SELECT q.*, u.username, e.name AS exam_name, s.name AS subject_name 
                         FROM questions q LEFT JOIN users u ON q.created_by = u.id 
                         JOIN subjects s ON q.subject_id = s.id LEFT JOIN exams e ON s.exam_id = e.id 
                         ORDER BY q.id DESC LIMIT %s OFFSET %s''', (per_page, offset))
        questions = cursor.fetchall()

        cursor.execute('SELECT COUNT(*) AS total FROM questions')
        total_questions = cursor.fetchone()['total']
        total_pages = (total_questions + per_page - 1) // per_page

        return render_template('manage_questions.html', questions=questions, subjects=subjects, form=form, page=page, total_pages=total_pages)
    
    except mysql.connector.Error as err:
        conn.rollback()
        logger.error(f"Database error in manage_questions: {str(err)}")
        flash('Error processing questions.', 'danger')
        return redirect(url_for('admin_dashboard'))
    finally:
        cursor.close()
        conn.close()

@app.route('/edit_question/<int:question_id>', methods=['GET', 'POST'])
@super_admin_required
@limiter.limit("50 per hour")
def edit_question(question_id):
    conn = get_db_connection()
    if conn is None:
        flash('Database connection error.', 'danger')
        return redirect(url_for('manage_questions'))
    
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute('SELECT id, name FROM subjects ORDER BY name')
        subjects = cursor.fetchall()
        form = QuestionForm()
        form.subject_id.choices = [(s['id'], s['name']) for s in subjects]

        cursor.execute('''SELECT q.*, s.name AS subject_name, s.exam_id 
                         FROM questions q JOIN subjects s ON q.subject_id = s.id 
                         WHERE q.id = %s''', (question_id,))
        question = cursor.fetchone()
        if not question:
            flash('Question not found.', 'danger')
            return redirect(url_for('manage_questions'))

        if request.method == 'GET':
            form.question.data = question['question']
            # Populate other fields similarly...
        elif form.validate_on_submit():
            topics_json = json.dumps([t.strip() for t in form.topics.data.split(',')]) if form.topics.data else '[]'
            cursor.execute('''UPDATE questions 
                            SET question = %s, option_a = %s, option_b = %s, option_c = %s, option_d = %s, 
                            correct_answer = %s, category = %s, difficulty = %s, subject_id = %s, 
                            is_previous_year = %s, previous_year = %s, topics = %s, explanation = %s 
                            WHERE id = %s''',
                            (sanitize_input(form.question.data), sanitize_input(form.option_a.data), sanitize_input(form.option_b.data),
                             sanitize_input(form.option_c.data), sanitize_input(form.option_d.data), form.correct_answer.data.upper(),
                             sanitize_input(form.category.data), form.difficulty.data, form.subject_id.data,
                             form.is_previous_year.data, form.previous_year.data if form.is_previous_year.data else None,
                             topics_json, sanitize_input(form.explanation.data), question_id))
            conn.commit()
            flash('Question updated successfully.', 'success')
            return redirect(url_for('manage_questions'))

        return render_template('edit_question.html', form=form, question_id=question_id)
    
    except mysql.connector.Error as err:
        conn.rollback()
        logger.error(f"Database error in edit_question: {str(err)}")
        flash('Error updating question.', 'danger')
        return redirect(url_for('manage_questions'))
    finally:
        cursor.close()
        conn.close()


@app.route('/delete_question/<int:qid>', methods=['POST'])
@super_admin_required
@limiter.limit("50 per hour")
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
            logger.info(f"Question {qid} deleted by superadmin {session['username']}")
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
@limiter.limit("50 per hour")
def edit_user(user_id):
    form = UserForm()
    conn = get_db_connection()
    if conn is None:
        flash('Database connection error.', 'danger')
        return redirect(url_for('manage_users'))
    
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
        user = cursor.fetchone()
        if not user:
            flash('User not found.', 'danger')
            return redirect(url_for('manage_users'))

        if user_id == session['user_id'] and user['role'] == 'superadmin' and request.method == 'POST' and form.role.data != 'superadmin':
            flash('You cannot downgrade your own superadmin role.', 'danger')
            return redirect(url_for('edit_user', user_id=user_id))

        if request.method == 'POST' and form.validate_on_submit():
            # Update logic...
            conn.commit()
            flash('User updated successfully.', 'success')
            return redirect(url_for('manage_users'))

        return render_template('edit_user.html', form=form, user_id=user_id)
    
    except mysql.connector.Error as err:
        conn.rollback()
        logger.error(f"Database error in edit_user: {str(err)}")
        flash('Error updating user.', 'danger')
        return redirect(url_for('manage_users'))
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

@app.route('/manage_users')
@super_admin_required
@limiter.limit("50 per hour")
def manage_users():
    user_type = request.args.get('type', 'all')
    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page

    conn = get_db_connection()
    if conn is None:
        flash('Database connection error.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    cursor = conn.cursor(dictionary=True)
    try:
        if user_type == 'all':
            cursor.execute('SELECT COUNT(*) AS total FROM users')
            total = cursor.fetchone()['total']
            cursor.execute('''SELECT role, COUNT(*) AS count, MAX(last_active) AS last_active 
                            FROM users GROUP BY role 
                            ORDER BY FIELD(role, 'superadmin', 'instituteadmin', 'student', 'individual') 
                            LIMIT %s OFFSET %s''', (per_page, offset))
            users = cursor.fetchall()
            total_pages = (total + per_page - 1) // per_page
            return render_template('manage_users.html', users=users, view_type='summary', current_type='all', page=page, total_pages=total_pages)

        elif user_type in ['individual', 'student', 'superadmin']:
            cursor.execute(f'SELECT COUNT(*) AS total FROM users WHERE role = %s', (user_type,))
            total = cursor.fetchone()['total']
            cursor.execute(f'''SELECT u.*, COUNT(DISTINCT r.id) AS quiz_count, 
                             AVG(r.score / r.total_questions * 100) AS avg_score, 
                             MAX(r.date_taken) AS last_quiz_date, i.name AS institution_name 
                             FROM users u LEFT JOIN results r ON u.id = r.user_id 
                             LEFT JOIN institutions i ON u.institution_id = i.id 
                             WHERE u.role = %s 
                             GROUP BY u.id ORDER BY u.username 
                             LIMIT %s OFFSET %s''', (user_type, per_page, offset))
            users = cursor.fetchall()
            total_pages = (total + per_page - 1) // per_page
            return render_template('manage_users.html', users=users, view_type='users', current_type=user_type, page=page, total_pages=total_pages)

        # Similar pagination for 'instituteadmin'...

    except mysql.connector.Error as err:
        logger.error(f"Database error in manage_users: {str(err)}")
        flash('Error retrieving users.', 'danger')
        return redirect(url_for('admin_dashboard'))
    finally:
        cursor.close()
        conn.close()

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@super_admin_required
@limiter.limit("50 per hour")
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
        conn.start_transaction()
        cursor.execute('SELECT role FROM users WHERE id = %s', (user_id,))
        user = cursor.fetchone()
        if not user:
            flash('User not found.', 'danger')
            return redirect(url_for('manage_users'))

        if user['role'] == 'superadmin':
            cursor.execute('SELECT COUNT(*) AS count FROM users WHERE role = "superadmin"')
            if cursor.fetchone()['count'] <= 1:
                flash('Cannot delete the last superadmin.', 'danger')
                return redirect(url_for('manage_users'))

        cursor.execute('DELETE FROM question_reviews WHERE user_id = %s', (user_id,))
        cursor.execute('DELETE FROM results WHERE user_id = %s', (user_id,))
        cursor.execute('DELETE FROM subscription_history WHERE user_id = %s', (user_id,))
        cursor.execute('DELETE FROM institution_students WHERE user_id = %s', (user_id,))
        cursor.execute('UPDATE institutions SET admin_id = NULL WHERE admin_id = %s', (user_id,))
        cursor.execute('DELETE FROM users WHERE id = %s', (user_id,))
        conn.commit()
        flash('User deleted successfully.', 'success')
    
    except mysql.connector.Error as err:
        conn.rollback()
        logger.error(f"Database error in delete_user: {str(err)}")
        flash('Error deleting user.', 'danger')
    finally:
        cursor.close()
        conn.close()
    return redirect(url_for('manage_users'))

@app.route('/subscriptions')
@login_required
@limiter.limit("50 per hour")
def subscriptions():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute('''SELECT u.subscription_plan_id, u.subscription_start, u.subscription_end, p.name as plan_name, p.price
            FROM users u
            LEFT JOIN subscription_plans p ON u.subscription_plan_id = p.id
            WHERE u.id = %s''', (session['user_id'],))
        user_subscription = cursor.fetchone()
        
        cursor.execute('SELECT * FROM subscription_plans WHERE is_institution = FALSE ORDER BY price')
        plans = cursor.fetchall()
        
        for plan in plans:
            cursor.execute('''SELECT e.id, e.name FROM plan_exam_access pea 
                            JOIN exams e ON pea.exam_id = e.id 
                            WHERE pea.plan_id = %s''', (plan['id'],))
            plan['exams'] = [{'id': row['id'], 'name': row['name']} for row in cursor.fetchall()]
            
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
@limiter.limit("50 per hour")
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
        
        cursor.execute('''SELECT e.id, e.name FROM plan_exam_access pea 
                        JOIN exams e ON pea.exam_id = e.id 
                        WHERE pea.plan_id = %s''', (plan_id,))
        plan['exams'] = [{'id': row['id'], 'name': row['name']} for row in cursor.fetchall()]
        
        if form.validate_on_submit():
            start_date = datetime.now().date()
            end_date = start_date + timedelta(days=plan['duration_days'])
                        
            cursor.execute('''UPDATE users 
                SET subscription_plan_id = %s,
                    subscription_start = %s,
                    subscription_end = %s,
                    subscription_status = %s,
                    last_active = %s
                WHERE id = %s''', (plan_id, start_date, end_date, 'active', datetime.now(), session['user_id']))
            
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
@limiter.limit("50 per hour")
def subscription_history():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute('''SELECT u.subscription_plan_id, u.subscription_start, u.subscription_end, 
                   p.name as plan_name, p.price, p.description
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

@app.route('/user_dashboard')
@login_required
@limiter.limit("50 per hour")
def user_dashboard():
    conn = get_db_connection()
    if conn is None:
        flash('Database connection error.', 'danger')
        return redirect(url_for('login'))
        
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute('''SELECT r.id, r.score, r.total_questions, r.time_taken, r.date_taken, e.name as exam_name
            FROM results r 
            LEFT JOIN exams e ON r.exam_id = e.id
            WHERE r.user_id = %s 
            ORDER BY r.date_taken DESC 
            LIMIT 5''',
            (session['user_id'],))
        recent_results = cursor.fetchall()
        
        cursor.execute('SELECT COUNT(*) as count FROM questions')
        result = cursor.fetchone()
        total_questions = result['count'] if result and 'count' in result else 0
        
        user_subscription = None
        accessible_exams = []
        
        if session.get('role') == 'individual':
            cursor.execute('''SELECT u.subscription_plan_id, u.subscription_start, u.subscription_end, 
                          p.name as plan_name, p.description
                FROM users u
                LEFT JOIN subscription_plans p ON u.subscription_plan_id = p.id
                WHERE u.id = %s''', (session['user_id'],))
            user_subscription = cursor.fetchone()
            
            if user_subscription and user_subscription['subscription_end'] and user_subscription['subscription_end'] > datetime.now():
                cursor.execute('''SELECT e.id, e.name FROM plan_exam_access pea 
                                JOIN exams e ON pea.exam_id = e.id 
                                WHERE pea.plan_id = %s''', (user_subscription['subscription_plan_id'],))
                accessible_exams = [{'id': row['id'], 'name': row['name']} for row in cursor.fetchall()]
        
        elif session.get('role') in ['student', 'superadmin', 'instituteadmin']:
            cursor.execute('SELECT id, name FROM exams')
            accessible_exams = [{'id': row['id'], 'name': row['name']} for row in cursor.fetchall()]
            
        if session.get('role') == 'instituteadmin':
            return redirect(url_for('institution_dashboard'))
        elif session.get('role') == 'superadmin':
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
@limiter.limit("50 per hour")
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
        cursor.execute('''SELECT r.id, r.score, r.total_questions, r.time_taken, r.date_taken, e.name as exam_name
            FROM results r 
            LEFT JOIN exams e ON r.exam_id = e.id
            WHERE r.user_id = %s 
            ORDER BY r.date_taken DESC''',
            (session['user_id'],))
        results = cursor.fetchall()
        
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['Result ID', 'Exam', 'Score', 'Total Questions', 'Percentage', 'Time Taken (seconds)', 'Date Taken'])
        
        for result in results:
            percentage = round((result['score'] / result['total_questions']) * 100, 1) if result['total_questions'] > 0 else 0
            writer.writerow([
                result['id'], 
                result['exam_name'] or 'Unknown', 
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

@app.route('/institution_dashboard')
@institute_admin_required
@limiter.limit("50 per hour")
def institution_dashboard():
    conn = get_db_connection()
    if conn is None:
        flash('Database connection error.', 'danger')
        return redirect(url_for('login'))
    
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Get institution details
        cursor.execute('''SELECT i.*, sp.name as plan_name, sp.description as plan_description
            FROM institutions i
            LEFT JOIN subscription_plans sp ON i.subscription_plan_id = sp.id
            WHERE i.id = %s''', (session['institution_id'],))
        institution = cursor.fetchone()
        
        # Get student stats
        cursor.execute('''SELECT COUNT(*) as student_count,
                         AVG(r.score / r.total_questions * 100) as avg_score,
                         COUNT(DISTINCT r.id) as quiz_count
            FROM users u
            LEFT JOIN results r ON u.id = r.user_id
            WHERE u.institution_id = %s AND u.role = 'student' ''', 
            (session['institution_id'],))
        stats = cursor.fetchone()
        
        # Get recent student results
        cursor.execute('''SELECT u.username, r.score, r.total_questions, r.date_taken, e.name as exam_name
            FROM users u
            LEFT JOIN results r ON u.id = r.user_id
            LEFT JOIN exams e ON r.exam_id = e.id
            WHERE u.institution_id = %s AND u.role = 'student'
            ORDER BY r.date_taken DESC
            LIMIT 5''', (session['institution_id'],))
        recent_results = cursor.fetchall()
        
        stats['avg_score'] = round(stats['avg_score'], 1) if stats['avg_score'] else 0
        
        return render_template('institution_dashboard.html',
                            institution=institution,
                            stats=stats,
                            recent_results=recent_results)
    except mysql.connector.Error as err:
        logger.error(f"Database error in institution dashboard: {str(err)}")
        flash('Error retrieving dashboard data.', 'danger')
        return render_template('institution_dashboard.html',
                            institution=None,
                            stats={'student_count': 0, 'avg_score': 0, 'quiz_count': 0},
                            recent_results=[])
    finally:
        cursor.close()
        conn.close()

@app.route('/admin_dashboard')
@super_admin_required
@limiter.limit("50 per hour")
def admin_dashboard():
    conn = get_db_connection()
    if conn is None:
        flash('Database connection error.', 'danger')
        return redirect(url_for('login'))
    
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Get overall stats
        cursor.execute('SELECT COUNT(*) as active_users FROM users WHERE status = "active"')
        active_users = cursor.fetchone()['active_users']
        
        cursor.execute('SELECT COUNT(*) as total_questions FROM questions')
        total_questions = cursor.fetchone()['total_questions']
        
        cursor.execute('SELECT COUNT(*) as total_quizzes FROM results')
        total_quizzes = cursor.fetchone()['total_quizzes']
        
        # Recent activity (aligned with template expectations)
        cursor.execute('''SELECT u.username, r.date_taken as date, 
                                 CONCAT('Score: ', r.score, '/', r.total_questions) as content,
                                 'result' as type
                          FROM results r
                          JOIN users u ON r.user_id = u.id
                          ORDER BY r.date_taken DESC
                          LIMIT 5''')
        recent_activity = cursor.fetchall()
        
        return render_template('admin_dashboard.html',
                              active_users=active_users,
                              total_questions=total_questions,
                              total_quizzes=total_quizzes,
                              recent_activity=recent_activity,
                              now=datetime.now())
    except mysql.connector.Error as err:
        logger.error(f"Database error in admin dashboard: {str(err)}")
        flash('Error retrieving dashboard data.', 'danger')
        return render_template('admin_dashboard.html',
                              active_users=0,
                              total_questions=0,
                              total_quizzes=0,
                              recent_activity=[],
                              now=datetime.now())
    finally:
        cursor.close()
        conn.close()


@app.route('/choose_login', methods=['GET', 'POST'])
def choose_login():
    form = LoginTypeForm()
    if form.validate_on_submit():
        login_type = form.login_type.data
        logger.info(f"Login type selected: {login_type}")
        if login_type == 'individual':
            return redirect(url_for('login'))
        elif login_type == 'institution':
            return redirect(url_for('institution_login'))
        elif login_type == 'student':
            return redirect(url_for('student_login'))
        else:
            flash('Invalid login type selected.', 'danger')
            logger.error(f"Unexpected login_type: {login_type}")
    return render_template('choose_login.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("50 per hour")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = sanitize_input(form.username.data)
        password = form.password.data
        
        conn = get_db_connection()
        if conn is None:
            flash('Database connection error.', 'danger')
            return redirect(url_for('login'))
        
        cursor = conn.cursor(dictionary=True)
        
        try:
            cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
            user = cursor.fetchone()
            
            if user and check_password_hash(user['password'], password):
                if user['status'] != 'active':
                    flash('Your account is not active.', 'danger')
                    return render_template('login.html', form=form)
                else:
                    session['username'] = user['username']
                    session['user_id'] = user['id']
                    session['role'] = user['role']
                    session.permanent = True
                    
                    cursor.execute('UPDATE users SET last_active = %s WHERE id = %s',
                                 (datetime.now(), user['id']))
                    conn.commit()
                    
                    logger.info(f"User {username} logged in successfully")
                    flash('Login successful!', 'success')
                    
                    # Role-based redirection
                    if user['role'] == 'superadmin':
                        return redirect(url_for('admin_dashboard'))
                    elif user['role'] == 'instituteadmin':
                        return redirect(url_for('institute_dashboard'))
                    else:
                        return redirect(url_for('user_dashboard'))
            else:
                flash('Invalid username or password.', 'danger')
        except mysql.connector.Error as err:
            logger.error(f"Database error during login: {str(err)}")
            flash('Error during login.', 'danger')
        finally:
            cursor.close()
            conn.close()
    
    return render_template('login.html', form=form)

@app.route('/institution_login', methods=['GET', 'POST'])
@limiter.limit("50 per hour")
def institution_login():
    form = InstitutionLoginForm()
    if form.validate_on_submit():
        institution_code = sanitize_input(form.institution_code.data)
        username = sanitize_input(form.username.data)
        password = form.password.data
        
        conn = get_db_connection()
        if conn is None:
            logger.error("Failed to get DB connection")
            flash('Database connection error.', 'danger')
            return redirect(url_for('institution_login'))
        
        cursor = conn.cursor(dictionary=True)
        
        try:
            cursor.execute('''SELECT u.*, i.id as institution_id 
                FROM users u
                JOIN institutions i ON u.id = i.admin_id
                WHERE u.username = %s AND i.institution_code = %s AND u.role = 'instituteadmin' ''',
                (username, institution_code))
            user = cursor.fetchone()
            
            if user:
                if check_password_hash(user['password'], password):
                    if user['status'] != 'active':
                        flash('Your account is not active.', 'danger')
                    else:
                        session['username'] = user['username']
                        session['user_id'] = user['id']
                        session['role'] = user['role']
                        session['institution_id'] = user['institution_id']
                        session.permanent = True
                        
                        cursor.execute('UPDATE users SET last_active = %s WHERE id = %s',
                                     (datetime.now(), user['id']))
                        conn.commit()
                        
                        logger.info(f"Institution admin {username} logged in successfully")
                        flash('Login successful!', 'success')
                        return redirect(url_for('institution_dashboard'))
                else:
                    flash('Invalid password.', 'danger')
            else:
                flash('Invalid username or institution code.', 'danger')
        except mysql.connector.Error as err:
            logger.error(f"Database error during institution login: {str(err)}")
            flash('Error during login.', 'danger')
        finally:
            cursor.close()
            conn.close()
    else:
        if request.method == 'POST':
            logger.debug(f"Form validation failed: {form.errors}")
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f"{field.capitalize()}: {error}", 'danger')
    
    return render_template('institution_login.html', form=form)

@app.route('/student_login', methods=['GET', 'POST'])
@limiter.limit("50 per hour")
def student_login():
    form = InstitutionLoginForm()
    if form.validate_on_submit():
        institution_code = sanitize_input(form.institution_code.data)
        username = sanitize_input(form.username.data)
        password = form.password.data
        
        conn = get_db_connection()
        if conn is None:
            flash('Database connection error.', 'danger')
            return redirect(url_for('student_login'))
        
        cursor = conn.cursor(dictionary=True)
        
        try:
            cursor.execute('''SELECT u.*, i.id as institution_id 
                FROM users u
                JOIN institution_students ist ON u.id = ist.user_id
                JOIN institutions i ON ist.institution_id = i.id
                WHERE u.username = %s AND i.institution_code = %s AND u.role = 'student' ''',
                (username, institution_code))
            user = cursor.fetchone()
            
            if user and check_password_hash(user['password'], password):
                if user['status'] != 'active':
                    flash('Your account is not active.', 'danger')
                else:
                    session['username'] = user['username']
                    session['user_id'] = user['id']
                    session['role'] = user['role']
                    session['institution_id'] = user['institution_id']
                    session.permanent = True
                    
                    cursor.execute('UPDATE users SET last_active = %s WHERE id = %s',
                                 (datetime.now(), user['id']))
                    conn.commit()
                    
                    logger.info(f"Student {username} logged in successfully")
                    flash('Login successful!', 'success')
                    return redirect(url_for('user_dashboard'))
            else:
                flash('Invalid credentials or institution code.', 'danger')
        except mysql.connector.Error as err:
            logger.error(f"Database error during student login: {str(err)}")
            flash('Error during login.', 'danger')
        finally:
            cursor.close()
            conn.close()
    
    return render_template('student_login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("50 per hour")
def register():
    form = RegisterForm()
    logger.debug(f"Register route accessed, method: {request.method}")
    if form.validate_on_submit():
        logger.debug("Form validated successfully")
        username = sanitize_input(form.username.data)
        email = sanitize_input(form.email.data)
        password = form.password.data
        
        conn = get_db_connection()
        if conn is None:
            logger.error("Failed to get DB connection")
            flash('Database connection error.', 'danger')
            return redirect(url_for('register'))
        
        cursor = conn.cursor(dictionary=True)
        
        try:
            cursor.execute('SELECT id FROM users WHERE username = %s OR email = %s', (username, email))
            if cursor.fetchone():
                logger.info(f"Registration attempt failed: Username {username} or email {email} already exists")
                flash('Username or email already exists.', 'danger')
            else:
                hashed_password = generate_password_hash(password)
                cursor.execute('''INSERT INTO users 
                    (username, email, password, role, user_type, status, degree, subscription_status, last_active) 
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)''',
                    (username, email, hashed_password, 'individual', 'individual', 'active', 'none', 'pending', datetime.now()))
                conn.commit()
                logger.info(f"New user registered: {username}")
                flash('Registration successful! Please log in.', 'success')
                return redirect(url_for('login'))
        except mysql.connector.Error as err:
            conn.rollback()
            logger.error(f"Database error during registration: {str(err)}")
            flash('Error during registration.', 'danger')
        finally:
            cursor.close()
            conn.close()
    else:
        if request.method == 'POST':
            logger.debug(f"Form validation failed: {form.errors}")
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f"{field.capitalize()}: {error}", 'danger')
    
    return render_template('register.html', form=form)

@app.route('/institution_register', methods=['GET', 'POST'])
@limiter.limit("50 per hour")
def institution_register():
    form = InstitutionRegisterForm()
    
    conn = get_db_connection()
    if conn is None:
        flash('Database connection error.', 'danger')
        return redirect(url_for('institution_register'))
    
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute('SELECT id, name FROM subscription_plans WHERE is_institution = TRUE')
        plans = cursor.fetchall()
        if not plans:
            flash('No institutional subscription plans available.', 'danger')
            return redirect(url_for('institution_register'))
        form.subscription_plan.choices = [(plan['id'], plan['name']) for plan in plans]
        
        if form.validate_on_submit():
            institution_name = sanitize_input(form.institution_name.data)
            admin_name = sanitize_input(form.admin_name.data)
            email = sanitize_input(form.email.data)
            username = sanitize_input(form.username.data)
            password = form.password.data
            subscription_plan_id = form.subscription_plan.data
            
            cursor.execute('SELECT id FROM users WHERE username = %s OR email = %s', (username, email))
            if cursor.fetchone():
                flash('Username or email already exists.', 'danger')
                return redirect(url_for('institution_register'))
            
            hashed_password = generate_password_hash(password)
            conn.start_transaction()
            
            # Insert admin user
            cursor.execute('''INSERT INTO users 
                (username, email, password, role, user_type, status, last_active) 
                VALUES (%s, %s, %s, %s, %s, %s, %s)''',
                (username, email, hashed_password, 'instituteadmin', 'institutional', 'active', datetime.now()))
            admin_id = cursor.lastrowid
            
            # Generate unique institution code
            while True:
                institution_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
                cursor.execute('SELECT id FROM institutions WHERE institution_code = %s', (institution_code,))
                if not cursor.fetchone():
                    break
            
            # Insert institution
            start_date = datetime.now()
            cursor.execute('SELECT duration_days FROM subscription_plans WHERE id = %s', (subscription_plan_id,))
            duration = cursor.fetchone()['duration_days']
            end_date = start_date + timedelta(days=duration)
            
            cursor.execute('''INSERT INTO institutions 
                (name, admin_id, subscription_plan_id, subscription_start, subscription_end, institution_code) 
                VALUES (%s, %s, %s, %s, %s, %s)''',
                (institution_name, admin_id, subscription_plan_id, start_date, end_date, institution_code))
            institution_id = cursor.lastrowid
            
            # Update user's institution_id
            cursor.execute('UPDATE users SET institution_id = %s WHERE id = %s', (institution_id, admin_id))
            
            conn.commit()
            
            logger.info(f"New institution registered: {institution_name} with admin {username}")
            flash(f'Registration successful! Your institution code is: {institution_code}', 'success')
            return redirect(url_for('institution_login'))
        
    except mysql.connector.Error as err:
        conn.rollback()
        logger.error(f"Database error during institution registration: {str(err)}")
        flash('Error during registration.', 'danger')
    finally:
        cursor.close()
        conn.close()
    
    if request.method == 'POST' and not form.validate():
        logger.debug(f"Form validation failed: {form.errors}")
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"{field.capitalize()}: {error}", 'danger')
    
    return render_template('institution_register.html', form=form)

@app.route('/student_register', methods=['GET', 'POST'])
@limiter.limit("50 per hour")
def student_register():
    form = StudentRegisterForm()
    if form.validate_on_submit():
        username = sanitize_input(form.username.data)
        email = sanitize_input(form.email.data)
        password = form.password.data
        institution_code = sanitize_input(form.institution_code.data)
        
        conn = get_db_connection()
        if conn is None:
            logger.error("Failed to get DB connection")
            flash('Database connection error.', 'danger')
            return redirect(url_for('student_register'))
        
        cursor = conn.cursor(dictionary=True)
        
        try:
            cursor.execute('SELECT id FROM users WHERE username = %s OR email = %s', (username, email))
            if cursor.fetchone():
                flash('Username or email already exists.', 'danger')
                return redirect(url_for('student_register'))
            
            cursor.execute('SELECT id, subscription_end FROM institutions WHERE institution_code = %s', (institution_code,))
            institution = cursor.fetchone()
            if not institution:
                flash('Invalid institution code.', 'danger')
                return redirect(url_for('student_register'))
            if institution['subscription_end'] and institution['subscription_end'] < datetime.now():
                flash('Institution subscription has expired.', 'danger')
                return redirect(url_for('student_register'))
            
            hashed_password = generate_password_hash(password)
            conn.start_transaction()
            
            cursor.execute('''INSERT INTO users 
                (username, email, password, role, user_type, status, institution_id, last_active) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)''',
                (username, email, hashed_password, 'student', 'institutional', 'active', institution['id'], datetime.now()))
            user_id = cursor.lastrowid
            
            cursor.execute('''INSERT INTO institution_students 
                (institution_id, user_id) 
                VALUES (%s, %s)''',
                (institution['id'], user_id))
            
            conn.commit()
            
            logger.info(f"New student {username} registered for institution {institution_code}")
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('student_login'))
        except mysql.connector.Error as err:
            conn.rollback()
            logger.error(f"Database error during student registration: {str(err)}")
            flash('Error during registration.', 'danger')
        finally:
            cursor.close()
            conn.close()
    else:
        if request.method == 'POST':
            logger.debug(f"Form validation failed: {form.errors}")
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f"{field.capitalize()}: {error}", 'danger')
    
    return render_template('student_register.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logger.info(f"User {session['username']} logged out")
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('choose_login'))

# SocketIO Events for Admin Dashboard
@socketio.on('connect', namespace='/admin')
def handle_connect():
    if session.get('role') in ['superadmin', 'instituteadmin']:
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
