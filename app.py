import pymysql
from flask import Flask, request, jsonify
from bcrypt import hashpw, gensalt, checkpw

app = Flask(__name__)

# Database connection using pymysql
conn = pymysql.connect(
    host="localhost",
    user="root",
    password="Saidulu76@",
    database="user_management"
)

# Register API
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data['username']
    email = data['email']
    password = data['password']

    try:
        with conn.cursor() as cursor:
            # Check if user already exists
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            if cursor.fetchone():
                return jsonify({"message": "Username already exists. Please choose another."}), 400

            # Hash the password
            hashed_password = hashpw(password.encode('utf-8'), gensalt())

            # Insert new user
            cursor.execute(
                "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                (username, email, hashed_password)
            )
            conn.commit()
            return jsonify({"message": "Registration successful!"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Login API
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data['username']
    password = data['password']

    try:
        with conn.cursor() as cursor:
            # Validate user credentials
            cursor.execute(
                "SELECT password FROM users WHERE username = %s", 
                (username,)
            )
            user = cursor.fetchone()

            if user and checkpw(password.encode('utf-8'), user[0].encode('utf-8')):
                # Simulate generating a token for session handling
                token = f"fake-token-for-{username}"
                return jsonify({"success": True, "token": token}), 200
            else:
                return jsonify({"success": False, "message": "Invalid credentials"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Dashboard API
@app.route('/dashboard', methods=['GET'])
def dashboard():
    token = request.headers.get('Authorization')
    if token and token.startswith("Bearer fake-token-for-"):
        username = token.split("Bearer fake-token-for-")[1]
        return jsonify({"message": f"Welcome to the dashboard, {username}!"}), 200
    else:
        return jsonify({"message": "Unauthorized access"}), 403


if __name__ == '__main__':
    app.run(debug=True, port=3000)
