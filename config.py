import os

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'default-secret-key-for-dev')
    MYSQL_HOST = os.getenv('MYSQL_HOST', 'localhost')
    MYSQL_USER = os.getenv('MYSQL_USER', 'root')
    MYSQL_PASSWORD = os.getenv('MYSQL_PASSWORD', 'newpass123')
    MYSQL_DB = os.getenv('MYSQL_DB', 'pharmacy_exam')
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