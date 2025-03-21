import mysql.connector
from dotenv import load_dotenv
import os
from werkzeug.security import generate_password_hash
import logging
import argparse
import time
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('init_db.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Database configuration (without database name initially)
db_config = {
    'host': os.getenv('MYSQL_HOST', 'localhost'),
    'user': os.getenv('MYSQL_USER', 'root'),
    'password': os.getenv('MYSQL_PASSWORD', ''),
    'auth_plugin': 'mysql_native_password'
}

def create_database_and_tables(reset_db=False):
    """
    Initialize the database and tables
    
    Args:
        reset_db (bool): If True, drops and recreates the database
    """
    try:
        # Connect to MySQL without specifying a database
        logger.info(f"Connecting to MySQL at {db_config['host']}...")
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()

        # Drop database if reset_db is True
        if reset_db:
            logger.warning("Dropping existing 'pharmacy_exam' database...")
            cursor.execute("DROP DATABASE IF EXISTS pharmacy_exam")
            logger.info("Database dropped successfully.")
        
        # Create the database if it doesn't exist
        cursor.execute("CREATE DATABASE IF NOT EXISTS pharmacy_exam")
        logger.info("Database 'pharmacy_exam' created or already exists.")
        
        # Switch to the database
        cursor.execute("USE pharmacy_exam")
        logger.info("Connected to 'pharmacy_exam' database.")

        # Create users table
        logger.info("Creating users table...")
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                role ENUM('user', 'admin') DEFAULT 'user',
                status ENUM('active', 'inactive') DEFAULT 'active',
                last_active DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_username (username),
                INDEX idx_role (role),
                INDEX idx_status (status),
                INDEX idx_last_active (last_active)
            )
        ''')
        
        # Create questions table
        logger.info("Creating questions table...")
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS questions (
                id INT AUTO_INCREMENT PRIMARY KEY,
                question TEXT NOT NULL,
                option_a VARCHAR(255) NOT NULL,
                option_b VARCHAR(255) NOT NULL,
                option_c VARCHAR(255) NOT NULL,
                option_d VARCHAR(255) NOT NULL,
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
            )
        ''')
        
        # Create results table
        logger.info("Creating results table...")
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS results (
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
            )
        ''')
        
        # Create question_reviews table
        logger.info("Creating question_reviews table...")
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS question_reviews (
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
            )
        ''')

        # Check for admin user and create if not exists
        cursor.execute('SELECT COUNT(*) FROM users WHERE role = "admin"')
        if cursor.fetchone()[0] == 0:
            admin_username = os.getenv('ADMIN_USERNAME', 'admin')
            admin_password = os.getenv('ADMIN_PASSWORD', 'admin123')
            hashed_password = generate_password_hash(admin_password)
            
            logger.info(f"Creating admin user '{admin_username}'...")
            cursor.execute('''
                INSERT INTO users (username, password, role, status, last_active) 
                VALUES (%s, %s, %s, %s, NOW())
            ''', (admin_username, hashed_password, 'admin', 'active'))
            logger.info("Admin user created successfully.")
        else:
            logger.info("Admin user already exists, skipping creation.")
        
        # Add sample user if specified
        if reset_db:
            logger.info("Creating sample user 'user'...")
            cursor.execute('''
                INSERT INTO users (username, password, role, status, last_active) 
                VALUES (%s, %s, %s, %s, NOW())
            ''', ('user', generate_password_hash('password123'), 'user', 'active'))
            logger.info("Sample user created successfully.")
        
        # Add sample questions if specified
        if reset_db:
            add_sample_questions(cursor)
        
        conn.commit()
        logger.info("Database and tables initialized successfully.")

    except mysql.connector.Error as err:
        logger.error(f"Error during database initialization: {str(err)}")
        sys.exit(1)
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()
            logger.info("Database connection closed.")

def add_sample_questions(cursor):
    """Add sample questions to the database"""
    try:
        logger.info("Adding sample questions...")
        
        # NAPLEX sample questions
        questions = [
            {
                'question': 'Which of the following antihypertensive medications is contraindicated in pregnancy?',
                'option_a': 'Labetalol',
                'option_b': 'Methyldopa',
                'option_c': 'Lisinopril',
                'option_d': 'Nifedipine',
                'correct_answer': 'c',
                'category': 'Pharmacology',
                'difficulty': 'medium',
                'exam_name': 'NAPLEX',
                'subject': 'Cardiovascular',
                'topics': 'Antihypertensives, Pregnancy',
                'year': 2023,
                'explanation': 'ACE inhibitors like lisinopril are contraindicated in pregnancy because they can cause fetal harm, particularly in the second and third trimesters.'
            },
            {
                'question': 'Which of the following antibiotics is most likely to cause photosensitivity?',
                'option_a': 'Doxycycline',
                'option_b': 'Amoxicillin',
                'option_c': 'Azithromycin',
                'option_d': 'Ceftriaxone',
                'correct_answer': 'a',
                'category': 'Pharmacology',
                'difficulty': 'easy',
                'exam_name': 'NAPLEX',
                'subject': 'Infectious Disease',
                'topics': 'Antibiotics, Adverse Effects',
                'year': 2023,
                'explanation': 'Tetracyclines, particularly doxycycline, are known to cause photosensitivity reactions. Patients should be advised to avoid sun exposure and use sunscreen.'
            },
            {
                'question': 'A 65-year-old patient with type 2 diabetes and CKD stage 3 would benefit most from which of the following antidiabetic medications?',
                'option_a': 'Metformin',
                'option_b': 'Glimepiride',
                'option_c': 'Empagliflozin',
                'option_d': 'Rosiglitazone',
                'correct_answer': 'c',
                'category': 'Therapeutics',
                'difficulty': 'hard',
                'exam_name': 'NAPLEX',
                'subject': 'Endocrinology',
                'topics': 'Diabetes, Kidney Disease',
                'year': 2024,
                'explanation': 'SGLT2 inhibitors like empagliflozin have shown cardiovascular and renal benefits in patients with type 2 diabetes and chronic kidney disease. They can slow the progression of kidney disease and reduce cardiovascular events.'
            },
            {
                'question': 'Which law established the "closed system" for controlled substances distribution?',
                'option_a': 'Durham-Humphrey Amendment',
                'option_b': 'Controlled Substances Act',
                'option_c': 'Prescription Drug Marketing Act',
                'option_d': 'Drug Quality and Security Act',
                'correct_answer': 'b',
                'category': 'Law',
                'difficulty': 'medium',
                'exam_name': 'MPJE',
                'subject': 'Pharmacy Law',
                'topics': 'Controlled Substances, Federal Law',
                'year': 2023,
                'explanation': 'The Controlled Substances Act of 1970 established a closed system of distribution for controlled substances, requiring registration with the DEA for all handlers of controlled substances.'
            },
            {
                'question': 'What is the primary mechanism of action of statins?',
                'option_a': 'Inhibition of HMG-CoA reductase',
                'option_b': 'Inhibition of cholesterol absorption',
                'option_c': 'Activation of lipoprotein lipase',
                'option_d': 'Inhibition of bile acid reabsorption',
                'correct_answer': 'a',
                'category': 'Pharmacology',
                'difficulty': 'easy',
                'exam_name': 'NAPLEX',
                'subject': 'Cardiovascular',
                'topics': 'Lipid-Lowering Agents, Mechanism of Action',
                'year': 2022,
                'explanation': 'Statins inhibit HMG-CoA reductase, the rate-limiting enzyme in cholesterol biosynthesis, thereby reducing endogenous cholesterol production and lowering serum LDL cholesterol levels.'
            },
            {
                'question': 'Which of the following is the most appropriate treatment for acute narrow-angle glaucoma?',
                'option_a': 'Timolol eye drops',
                'option_b': 'Latanoprost eye drops',
                'option_c': 'Pilocarpine eye drops',
                'option_d': 'Artificial tears',
                'correct_answer': 'c',
                'category': 'Therapeutics',
                'difficulty': 'medium',
                'exam_name': 'NAPLEX',
                'subject': 'Ophthalmology',
                'topics': 'Glaucoma, Emergency Treatment',
                'year': 2023,
                'explanation': 'Pilocarpine, a cholinergic agonist, constricts the pupil (miosis) and opens the trabecular meshwork, facilitating aqueous humor drainage. It is used in the acute management of narrow-angle glaucoma.'
            }
        ]
        
        # Get admin user ID
        cursor.execute("SELECT id FROM users WHERE role = 'admin' LIMIT 1")
        admin_id = cursor.fetchone()[0]
        
        # Insert sample questions
        for q in questions:
            cursor.execute('''
                INSERT INTO questions 
                (question, option_a, option_b, option_c, option_d, correct_answer, 
                category, difficulty, exam_name, subject, topics, year, explanation, created_by)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ''', (
                q['question'], q['option_a'], q['option_b'], q['option_c'], q['option_d'], 
                q['correct_answer'], q['category'], q['difficulty'], q['exam_name'], 
                q['subject'], q['topics'], q['year'], q['explanation'], admin_id
            ))
        
        logger.info(f"Added {len(questions)} sample questions successfully.")
    except mysql.connector.Error as err:
        logger.error(f"Error adding sample questions: {str(err)}")
        raise

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Initialize the database for the Pharmacy Exam Prep application')
    parser.add_argument('--reset', action='store_true', help='Reset the database (drop and recreate)')
    args = parser.parse_args()
    
    logger.info("Starting database initialization...")
    start_time = time.time()
    
    try:
        create_database_and_tables(reset_db=args.reset)
        elapsed_time = time.time() - start_time
        logger.info(f"Database initialization completed in {elapsed_time:.2f} seconds.")
    except Exception as e:
        logger.error(f"Unexpected error during initialization: {str(e)}")
        sys.exit(1)