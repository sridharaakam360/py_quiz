# test_env.py
from dotenv import load_dotenv
import os

load_dotenv()
print(f"MYSQL_USER: {os.getenv('MYSQL_USER')}")
print(f"MYSQL_PASSWORD: {os.getenv('MYSQL_PASSWORD')}")
print(f"MYSQL_HOST: {os.getenv('MYSQL_HOST')}")
print(f"MYSQL_DB: {os.getenv('MYSQL_DB')}")


INSERT INTO users (username, password, role) VALUES ('testuser', 'hashedpassword', 'user');