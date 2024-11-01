import sqlite3
import hashlib
from flask import Flask, request, jsonify
from functools import wraps

app = Flask(__name__)

# Connect to SQLite database (or create it if it doesn't exist)
conn = sqlite3.connect("pizza_delivery.db", check_same_thread=False)
cursor = conn.cursor()

# Create tables for users, orders, and notifications
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT DEFAULT 'user'  -- Default role for users
    )
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS orders (
        order_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        pizza_type TEXT,
        quantity INTEGER,
        status TEXT DEFAULT 'Pending',
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS notifications (
        notification_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        message TEXT,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
''')

# Commit table creation
conn.commit()

# Hashing function
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Decorator to check if user is logged in
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        username = request.headers.get("Authorization")
        if not username:
            return jsonify({"message": "Authorization header missing"}), 403
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if not cursor.fetchone():
            return jsonify({"message": "User not logged in"}), 403
        return f(*args, **kwargs)
    return decorated_function

# Home route
@app.route('/')
def home():
    return jsonify({"message": "Welcome to the Pizza Delivery App!"}), 200

# Register endpoint
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    hashed_password = hash_password(password)

    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        return jsonify({"message": "User registered successfully"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"message": "Username already exists"}), 409

# Login endpoint
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if username == "aryan" and password == "aryan24":
        return jsonify({"message": "Admin logged in"}), 200
    
    hashed_password = hash_password(password)
    cursor.execute("SELECT id FROM users WHERE username = ? AND password = ?", (username, hashed_password))
    user = cursor.fetchone()
    if user:
        return jsonify({"message": "User logged in", "user_id": user[0]}), 200
    return jsonify({"message": "Invalid credentials"}), 401

# Create order endpoint
@app.route('/order', methods=['POST'])
@login_required
def create_order():
    data = request.get_json()
    pizza_type = data.get("pizza_type")
    quantity = data.get("quantity")
    username = request.headers.get("Authorization")

    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    user_id = cursor.fetchone()[0]
    
    cursor.execute("INSERT INTO orders (user_id, pizza_type, quantity) VALUES (?, ?, ?)", (user_id, pizza_type, quantity))
    conn.commit()
    return jsonify({"message": "Order created successfully"}), 201

# View orders endpoint
@app.route('/orders', methods=['GET'])
@login_required
def view_orders():
    username = request.headers.get("Authorization")
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    user_id = cursor.fetchone()[0]

    cursor.execute("SELECT order_id, pizza_type, quantity, status FROM orders WHERE user_id = ?", (user_id,))
    orders = cursor.fetchall()
    
    return jsonify({"orders": [{"order_id": order[0], "pizza_type": order[1], "quantity": order[2], "status": order[3]} for order in orders]}), 200

# Admin view all orders
@app.route('/admin/orders', methods=['GET'])
@login_required
def admin_view_orders():
    username = request.headers.get("Authorization")
    if username != "aryan":
        return jsonify({"message": "Unauthorized"}), 403

    cursor.execute("SELECT o.order_id, u.username, o.pizza_type, o.quantity, o.status FROM orders o JOIN users u ON o.user_id = u.id")
    orders = cursor.fetchall()

    return jsonify({"orders": [{"order_id": order[0], "username": order[1], "pizza_type": order[2], "quantity": order[3], "status": order[4]} for order in orders]}), 200

# Main program entry
if __name__ == '__main__':
    app.run(debug=True)

# Close the database connection when the application exits
@app.teardown_appcontext
def close_connection(exception):
    conn.close()
