# Updates for config.py
import os

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'default-secret-key-for-dev')
    MYSQL_HOST = os.getenv('MYSQL_HOST', 'localhost')
    MYSQL_USER = os.getenv('MYSQL_USER', 'root')
    MYSQL_PASSWORD = os.getenv('MYSQL_PASSWORD', 'newpass123')
    MYSQL_DB = os.getenv('MYSQL_DB', 'exit_database')  # Updated DB name
    DEBUG = False
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

class DevelopmentConfig(Config):
    DEBUG = True
    SESSION_COOKIE_SECURE = False

class ProductionConfig(Config):
    pass

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig
}

# Update in app.py
db_config = {
    'pool_name': 'pharmacy_pool',
    'pool_size': 20,
    'host': os.getenv('MYSQL_HOST', 'localhost'),
    'user': os.getenv('MYSQL_USER', 'root'),
    'password': os.getenv('MYSQL_PASSWORD', ''),
    'database': 'exit_database',  # Updated database name
    'raise_on_warnings': True,
    'autocommit': False,
    'use_pure': True,
    'connection_timeout': 30
}