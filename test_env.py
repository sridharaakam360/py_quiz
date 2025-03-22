


INSERT INTO users (username, password, role) VALUES ('testuser', 'hashedpassword', 'user');



# Add to the init_db function in app.py:

cursor.execute('''
    CREATE TABLE IF NOT EXISTS subscription_plans (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        price DECIMAL(10, 2) NOT NULL,
        duration_days INT NOT NULL,
        max_users INT DEFAULT 1,
        features TEXT,
        is_institution BOOLEAN DEFAULT FALSE,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS institutions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        admin_id INT,
        subscription_plan_id INT,
        user_limit INT DEFAULT 0,
        subscription_start DATETIME,
        subscription_end DATETIME,
        status ENUM('active', 'inactive', 'expired') DEFAULT 'active',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (admin_id) REFERENCES users(id) ON DELETE SET NULL,
        FOREIGN KEY (subscription_plan_id) REFERENCES subscription_plans(id) ON DELETE SET NULL,
        INDEX idx_status (status),
        INDEX idx_subscription_end (subscription_end)
    )
''')

# Modify the users table to add institution relationship:
cursor.execute('''
    ALTER TABLE users 
    ADD COLUMN user_type ENUM('individual', 'institution_admin', 'institution_student') DEFAULT 'individual',
    ADD COLUMN institution_id INT,
    ADD COLUMN subscription_plan_id INT,
    ADD COLUMN subscription_start DATETIME,
    ADD COLUMN subscription_end DATETIME,
    ADD FOREIGN KEY (institution_id) REFERENCES institutions(id) ON DELETE SET NULL,
    ADD FOREIGN KEY (subscription_plan_id) REFERENCES subscription_plans(id) ON DELETE SET NULL,
    ADD INDEX idx_user_type (user_type),
    ADD INDEX idx_subscription_end (subscription_end)
''')

# Add subscription history table:
cursor.execute('''
    CREATE TABLE IF NOT EXISTS subscription_history (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        institution_id INT,
        subscription_plan_id INT,
        amount_paid DECIMAL(10, 2),
        payment_method VARCHAR(50),
        transaction_id VARCHAR(100),
        start_date DATETIME,
        end_date DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
        FOREIGN KEY (institution_id) REFERENCES institutions(id) ON DELETE SET NULL,
        FOREIGN KEY (subscription_plan_id) REFERENCES subscription_plans(id) ON DELETE SET NULL,
        INDEX idx_user_id (user_id),
        INDEX idx_institution_id (institution_id)
    )
''')

# Insert default subscription plans
cursor.execute('''
    INSERT INTO subscription_plans (name, price, duration_days, max_users, features, is_institution)
    VALUES 
    ('Basic Individual', 49.99, 30, 1, 'Access to all basic features', FALSE),
    ('Premium Individual', 99.99, 90, 1, 'Access to all premium features', FALSE),
    ('Annual Individual', 299.99, 365, 1, 'Full access to all features for a year', FALSE),
    ('Institution Basic', 499.99, 180, 25, 'Basic access for institutions', TRUE),
    ('Institution Premium', 999.99, 365, 100, 'Premium access for institutions', TRUE),
    ('Institution Enterprise', 2499.99, 365, 500, 'Enterprise access for large institutions', TRUE)
''')