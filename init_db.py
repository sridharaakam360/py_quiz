-- Create the chemist database
CREATE DATABASE IF NOT EXISTS chemist CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE chemist;

-- Users table - core user information
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role ENUM('individual_user', 'student_user', 'institute_admin', 'super_admin') DEFAULT 'individual_user',
    status ENUM('active', 'inactive', 'suspended') DEFAULT 'active',
    user_type ENUM('individual', 'institution_admin', 'institution_student') DEFAULT 'individual',
    institution_id INT NULL,
    subscription_plan_id INT NULL,
    subscription_start DATETIME NULL,
    subscription_end DATETIME NULL,
    last_active DATETIME NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    profile_image VARCHAR(255) NULL,
    preferences JSON NULL,
    INDEX idx_username (username),
    INDEX idx_email (email),
    INDEX idx_role (role),
    INDEX idx_status (status),
    INDEX idx_user_type (user_type),
    INDEX idx_institution_id (institution_id),
    INDEX idx_subscription (subscription_plan_id, subscription_end),
    INDEX idx_last_active (last_active)
);

-- Institutions table - for managing educational institutions
CREATE TABLE institutions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    admin_id INT NULL,
    institution_code VARCHAR(20) UNIQUE NOT NULL,
    description TEXT NULL,
    logo_url VARCHAR(255) NULL,
    website VARCHAR(255) NULL,
    address TEXT NULL,
    subscription_plan_id INT NULL,
    user_limit INT DEFAULT 50,
    subscription_start DATETIME NULL,
    subscription_end DATETIME NULL,
    status ENUM('active', 'inactive', 'suspended') DEFAULT 'active',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_name (name),
    INDEX idx_institution_code (institution_code),
    INDEX idx_admin_id (admin_id),
    INDEX idx_subscription (subscription_plan_id, subscription_end),
    INDEX idx_status (status)
);

-- Add foreign key relationships for users
ALTER TABLE users
ADD CONSTRAINT fk_users_institution
FOREIGN KEY (institution_id) REFERENCES institutions(id) ON DELETE SET NULL;

-- Add foreign key relationships for institutions
ALTER TABLE institutions
ADD CONSTRAINT fk_institutions_admin
FOREIGN KEY (admin_id) REFERENCES users(id) ON DELETE SET NULL;

-- Subscription plans table - defines available subscription options
CREATE TABLE subscription_plans (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT NULL,
    price DECIMAL(10, 2) NOT NULL,
    duration_days INT NOT NULL,
    max_users INT DEFAULT 1,
    is_institution BOOLEAN DEFAULT FALSE,
    is_popular BOOLEAN DEFAULT FALSE,
    features JSON NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_is_institution (is_institution),
    INDEX idx_is_popular (is_popular)
);

-- Add foreign key relationships for subscription plans
ALTER TABLE users
ADD CONSTRAINT fk_users_subscription_plan
FOREIGN KEY (subscription_plan_id) REFERENCES subscription_plans(id) ON DELETE SET NULL;

ALTER TABLE institutions
ADD CONSTRAINT fk_institutions_subscription_plan
FOREIGN KEY (subscription_plan_id) REFERENCES subscription_plans(id) ON DELETE SET NULL;

-- Plan exam access - links subscription plans to specific exams
CREATE TABLE plan_exam_access (
    id INT AUTO_INCREMENT PRIMARY KEY,
    plan_id INT NOT NULL,
    exam_name VARCHAR(100) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (plan_id) REFERENCES subscription_plans(id) ON DELETE CASCADE,
    UNIQUE KEY idx_plan_exam (plan_id, exam_name),
    INDEX idx_exam_name (exam_name)
);

-- Subscription history - tracks all subscription activities
CREATE TABLE subscription_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    institution_id INT NULL,
    subscription_plan_id INT NOT NULL,
    start_date DATETIME NOT NULL,
    end_date DATETIME NOT NULL,
    amount_paid DECIMAL(10, 2) NOT NULL,
    payment_method VARCHAR(50) NOT NULL,
    transaction_id VARCHAR(100) NULL,
    invoice_id VARCHAR(100) NULL,
    payment_status ENUM('pending', 'completed', 'failed', 'refunded') DEFAULT 'completed',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (institution_id) REFERENCES institutions(id) ON DELETE SET NULL,
    FOREIGN KEY (subscription_plan_id) REFERENCES subscription_plans(id) ON DELETE RESTRICT,
    INDEX idx_user_id (user_id),
    INDEX idx_institution_id (institution_id),
    INDEX idx_subscription_plan_id (subscription_plan_id),
    INDEX idx_dates (start_date, end_date),
    INDEX idx_payment_status (payment_status)
);

-- Questions table - stores all exam questions
CREATE TABLE questions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    question TEXT NOT NULL,
    option_a VARCHAR(255) NOT NULL,
    option_b VARCHAR(255) NOT NULL,
    option_c VARCHAR(255) NOT NULL,
    option_d VARCHAR(255) NOT NULL,
    correct_answer CHAR(1) NOT NULL,
    category VARCHAR(50) NOT NULL,
    difficulty ENUM('easy', 'medium', 'hard') DEFAULT 'medium',
    difficulty_rating DECIMAL(3,2) NULL COMMENT 'Calculated difficulty based on user performance',
    exam_name VARCHAR(100) NOT NULL,
    subject VARCHAR(100) NOT NULL,
    topics VARCHAR(255) NOT NULL,
    tags VARCHAR(255) NULL COMMENT 'Comma-separated tags for improved searching',
    year INT NOT NULL,
    explanation TEXT NOT NULL,
    reference_source VARCHAR(255) NULL,
    image_url VARCHAR(255) NULL,
    meta_data JSON NULL,
    created_by INT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_exam_year (exam_name, year),
    INDEX idx_subject (subject),
    INDEX idx_difficulty (difficulty),
    INDEX idx_difficulty_rating (difficulty_rating),
    INDEX idx_category (category),
    INDEX idx_tags (tags(191)),
    INDEX idx_created_at (created_at),
    FULLTEXT INDEX ft_question (question, explanation, topics)
);

-- Question categories table - for hierarchical organization of questions
CREATE TABLE question_categories (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    slug VARCHAR(100) NOT NULL,
    parent_id INT NULL,
    description TEXT NULL,
    icon VARCHAR(50) NULL,
    display_order INT DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (parent_id) REFERENCES question_categories(id) ON DELETE SET NULL,
    UNIQUE KEY idx_slug (slug),
    INDEX idx_name (name),
    INDEX idx_parent_id (parent_id),
    INDEX idx_display_order (display_order)
);

-- Category question linking table - for many-to-many relationships
CREATE TABLE category_question (
    category_id INT NOT NULL,
    question_id INT NOT NULL,
    PRIMARY KEY (category_id, question_id),
    FOREIGN KEY (category_id) REFERENCES question_categories(id) ON DELETE CASCADE,
    FOREIGN KEY (question_id) REFERENCES questions(id) ON DELETE CASCADE
);

-- Question statistics table - for tracking performance metrics
CREATE TABLE question_stats (
    id INT AUTO_INCREMENT PRIMARY KEY,
    question_id INT NOT NULL,
    times_presented INT DEFAULT 0,
    times_answered_correctly INT DEFAULT 0,
    average_answer_time INT NULL COMMENT 'Average time in seconds',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (question_id) REFERENCES questions(id) ON DELETE CASCADE,
    INDEX idx_question_id (question_id),
    INDEX idx_performance (times_presented, times_answered_correctly)
);

-- Quiz results table - stores user quiz attempts
CREATE TABLE results (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    score INT NOT NULL,
    total_questions INT NOT NULL,
    time_taken INT NOT NULL,
    answers JSON NULL,
    quiz_type VARCHAR(50) NULL,
    exam_name VARCHAR(100) NULL,
    subject VARCHAR(100) NULL,
    date_taken DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_date_taken (date_taken),
    INDEX idx_exam_name (exam_name),
    INDEX idx_subject (subject)
);

-- Question reviews table - for user feedback on questions
CREATE TABLE question_reviews (
    id INT AUTO_INCREMENT PRIMARY KEY,
    question_id INT NOT NULL,
    user_id INT NOT NULL,
    comment TEXT NULL,
    rating INT NOT NULL CHECK (rating >= 1 AND rating <= 5),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (question_id) REFERENCES questions(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY idx_user_question (user_id, question_id),
    INDEX idx_question_id (question_id),
    INDEX idx_user_id (user_id),
    INDEX idx_rating (rating)
);

-- Study progress table - tracks user progress through topics
CREATE TABLE study_progress (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    subject VARCHAR(100) NOT NULL,
    topic VARCHAR(100) NOT NULL,
    progress_percentage DECIMAL(5,2) DEFAULT 0.00,
    completed_questions INT DEFAULT 0,
    correct_answers INT DEFAULT 0,
    last_activity DATETIME NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY idx_user_topic (user_id, subject, topic),
    INDEX idx_user_id (user_id),
    INDEX idx_subject (subject),
    INDEX idx_topic (topic),
    INDEX idx_progress (progress_percentage)
);

-- Custom quizzes table - for saved quiz configurations
CREATE TABLE custom_quizzes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    name VARCHAR(100) NOT NULL,
    description TEXT NULL,
    configuration JSON NOT NULL,
    is_favorite BOOLEAN DEFAULT FALSE,
    times_taken INT DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_is_favorite (is_favorite)
);

-- Notifications table - for system and user notifications
CREATE TABLE notifications (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    institution_id INT NULL,
    type ENUM('subscription_expiring', 'subscription_renewed', 'subscription_canceled', 'payment_failed', 'system_update', 'new_content', 'achievement') NOT NULL,
    title VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    is_read BOOLEAN DEFAULT FALSE,
    action_url VARCHAR(255) NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (institution_id) REFERENCES institutions(id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_institution_id (institution_id),
    INDEX idx_is_read (is_read),
    INDEX idx_type (type),
    INDEX idx_created_at (created_at)
);

-- User activity logs - tracks important user actions
CREATE TABLE user_activity_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    activity_type VARCHAR(50) NOT NULL,
    description TEXT NULL,
    ip_address VARCHAR(45) NULL,
    user_agent TEXT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_activity_type (activity_type),
    INDEX idx_created_at (created_at)
);

-- System settings table - for application configuration
CREATE TABLE system_settings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    setting_key VARCHAR(100) UNIQUE NOT NULL,
    setting_value TEXT NOT NULL,
    data_type ENUM('string', 'integer', 'float', 'boolean', 'json') DEFAULT 'string',
    description TEXT NULL,
    is_public BOOLEAN DEFAULT FALSE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_setting_key (setting_key),
    INDEX idx_is_public (is_public)
);

-- Question import history - tracks bulk imports
CREATE TABLE question_import_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    filename VARCHAR(255) NOT NULL,
    total_records INT DEFAULT 0,
    successful_imports INT DEFAULT 0,
    failed_imports INT DEFAULT 0,
    error_log TEXT NULL,
    status ENUM('pending', 'processing', 'completed', 'failed') DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_status (status),
    INDEX idx_created_at (created_at)
);

-- User achievements table - for gamification
CREATE TABLE user_achievements (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    achievement_key VARCHAR(50) NOT NULL,
    achievement_name VARCHAR(100) NOT NULL,
    description TEXT NULL,
    awarded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY idx_user_achievement (user_id, achievement_key),
    INDEX idx_user_id (user_id),
    INDEX idx_achievement_key (achievement_key),
    INDEX idx_awarded_at (awarded_at)
);

-- Create initial super admin user
INSERT INTO users (username, email, password, role, status, last_active)
VALUES ('superadmin', 'admin@chemist.com', '$2b$12$1xxxxxxxxxxxxxxxxxxxxuxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx', 'super_admin', 'active', NOW());