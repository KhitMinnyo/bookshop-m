from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Initialize database
def init_db():
    conn = sqlite3.connect('bookshop.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS books
                 (id INTEGER PRIMARY KEY, title TEXT, author TEXT, price REAL, image TEXT, description TEXT)''')
    
    # Add sample books if table is empty
    c.execute('SELECT COUNT(*) FROM books')
    if c.fetchone()[0] == 0:
        books = [
            ('Basic Hacking Techniques', 'Khit Minnyo', 29.99, 'book1.jpg', 'A comprehensive guide to basic hacking techniques.'),
            ('Grade 3 Hacking', 'Khit Minnyo', 24.99, 'book2.jpg', 'Advanced hacking techniques for experienced practitioners.'),
            ('WiFi Hacking', 'Khit Minnyo', 19.99, 'book3.jpg', 'Learn the art of wireless network security.'),
            ('The First Step Towards Hacking', 'Khit Minnyo', 22.99, 'book4.png', 'Begin your journey into ethical hacking.'),
            ('Linux For Hackers', 'Khit Minnyo', 21.99, 'book5.png', 'Master Linux for security testing.'),
            ('Networking For Hackers', 'Khit Minnyo', 23.99, 'book6.png', 'Network fundamentals for security professionals.')
        ]
        c.executemany('INSERT INTO books (title, author, price, image, description) VALUES (?, ?, ?, ?, ?)', books)
    
    # Create users table with new flag
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, 
                  username TEXT UNIQUE, 
                  email TEXT UNIQUE,
                  password TEXT,
                  credit_card_number TEXT,
                  credit_card_expiry TEXT,
                  credit_card_cvv TEXT,
                  balance REAL DEFAULT 1000.0,
                  secret_note TEXT)''')
    
    # Add sample users if table is empty
    c.execute('SELECT COUNT(*) FROM users')
    if c.fetchone()[0] == 0:
        users = [
            ('admin', 'admin@bookshop.com', 'SuperSecurePass2025!', '4532-0000-0000-0000', '01/25', '999', 9999.0, 'CTF{Bl1nd_SQL1_M4st3r_T1m3_B4s3d_2025}'),
            ('alice_hacker', 'alice@hack.com', 'password123', '4532-1234-5678-9012', '12/25', '123', 1500.0, 'Just a regular note'),
            ('bob_secure', 'bob@secure.net', 'password456', '4532-9876-5432-1098', '03/26', '456', 2000.0, 'Nothing special here'),
            ('charlie_cyber', 'charlie@cyber.org', 'password789', '4532-4567-8901-2345', '06/25', '789', 1200.0, 'My secret shopping list'),
            ('david_code', 'david@code.com', 'passwordabc', '4532-3456-7890-1234', '09/26', '012', 1800.0, 'Remember to update password'),
            ('eve_binary', 'eve@binary.net', 'passworddef', '4532-2345-6789-0123', '11/25', '345', 2500.0, 'Binary is life!')
        ]
        c.executemany('INSERT INTO users (username, email, password, credit_card_number, credit_card_expiry, credit_card_cvv, balance, secret_note) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', users)

    # Create cart table
    c.execute('''CREATE TABLE IF NOT EXISTS cart
                 (id INTEGER PRIMARY KEY,
                  user_id INTEGER,
                  book_id INTEGER,
                  quantity INTEGER DEFAULT 1,
                  FOREIGN KEY (user_id) REFERENCES users (id),
                  FOREIGN KEY (book_id) REFERENCES books (id))''')

    conn.commit()
    conn.close()

def get_cart_count():
    if 'user_id' not in session:
        return 0
    conn = sqlite3.connect('bookshop.db')
    c = conn.cursor()
    c.execute('SELECT SUM(quantity) FROM cart WHERE user_id = ?', (session['user_id'],))
    count = c.fetchone()[0]
    conn.close()
    return count or 0

# Simplified WAF implementation
def waf_check(input_str):
    if not input_str:
        return False
        
    # Convert input to lowercase for checking
    input_lower = input_str.lower()
    
    # First, check for MySQL-style comments and allow them
    if "/*!50000" in input_lower:
        print("DEBUG: Allowing MySQL-style comment")
        return False
    
    # Blacklist of SQL injection patterns (case-insensitive)
    blacklist = [
        "union", "select", "from", "where",
        "drop", "delete", "insert", "update", "alter",
        "/*", "*/", "#", "--", "xp_", "sp_",
        "sleep", "benchmark", "wait", "delay"
    ]
    
    # Check for SQL injection patterns
    for pattern in blacklist:
        if pattern in input_lower:
            print(f"WAF blocked pattern: {pattern}")
            return True
            
    return False

# Custom WAF bypass check (intentionally vulnerable to specific patterns)
def bypass_check(input_str):
    # The WAF can be bypassed by using:
    # 1. Double encoding
    # 2. Unicode alternative characters
    # 3. Specific concatenation patterns
    
    # Intentionally vulnerable to double-encoded characters
    double_encoded = {
        '%2527': "'",      # Double-encoded single quote
        '%252F': "/",      # Double-encoded forward slash
        '%2553': "S",      # Double-encoded S
        '%2555': "U",      # Double-encoded U
    }
    
    # Check for double encoding bypass attempts
    for encoded, char in double_encoded.items():
        if encoded.lower() in input_str.lower():
            return True
            
    # Vulnerable to specific unicode alternatives
    unicode_chars = {
        'ᵁNION',      # Unicode lookalike
        'ＳＥＬＥＣＴ',  # Full-width characters
        'սɴɪօɴ',      # Mixed unicode
    }
    
    for char in unicode_chars:
        if char in input_str:
            return True
            
    return False

@app.route('/')
def index():
    conn = sqlite3.connect('bookshop.db')
    c = conn.cursor()
    c.execute('SELECT * FROM books')
    books = c.fetchall()
    conn.close()
    cart_count = get_cart_count()
    return render_template('index.html', books=books, session=session, cart_count=cart_count)

@app.route('/books')
def books():
    conn = sqlite3.connect('bookshop.db')
    c = conn.cursor()
    search = request.args.get('search', '')
    
    # Using parameterized query for safe search
    try:
        books = c.execute('SELECT * FROM books WHERE title LIKE ? OR author LIKE ?', 
                         (f'%{search}%', f'%{search}%')).fetchall()
    except:
        books = []
        flash('An error occurred while searching.', 'error')
    conn.close()
    cart_count = get_cart_count()
    return render_template('books.html', books=books, search=search, session=session, cart_count=cart_count)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('bookshop.db')
        c = conn.cursor()
        
        try:
            # First try secure login
            c.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))
            user = c.fetchone()
            
            if user:
                session['user_id'] = user[0]
                session['username'] = user[1]
                flash('Login successful!', 'success')
                return redirect(url_for('index'))
            
            # If secure login fails, try the vulnerable path (for CTF purposes)
            if not waf_check(username) and not waf_check(password):
                query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
                user = c.execute(query).fetchone()
                
                if user:
                    session['user_id'] = user[0]
                    session['username'] = user[1]
                    flash('Login successful!', 'success')
                    return redirect(url_for('index'))
            else:
                flash('WAF Detection: Potential SQL injection detected!', 'danger')
                
            flash('Invalid username or password', 'danger')
        except Exception as e:
            flash('An error occurred during login.', 'danger')
        finally:
            conn.close()
                
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash('Please login first.', 'danger')
        return redirect(url_for('login'))
        
    conn = sqlite3.connect('bookshop.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
    user = c.fetchone()
    conn.close()
    cart_count = get_cart_count()
    return render_template('profile.html', user=user, session=session, cart_count=cart_count)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        credit_card_number = request.form['credit_card_number']
        credit_card_expiry = request.form['credit_card_expiry']
        credit_card_cvv = request.form['credit_card_cvv']
        
        # Check if username or email already exists
        conn = sqlite3.connect('bookshop.db')
        c = conn.cursor()
        
        # Check for existing username or email
        c.execute('SELECT * FROM users WHERE username = ? OR email = ?', (username, email))
        existing_user = c.fetchone()
        
        if existing_user:
            flash('Username or email already exists!', 'danger')
            conn.close()
            return render_template('register.html')
        
        try:
            c.execute('INSERT INTO users (username, email, password, credit_card_number, credit_card_expiry, credit_card_cvv, balance, secret_note) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                     (username, email, password, credit_card_number, credit_card_expiry, credit_card_cvv, 1000.0, 'Welcome to the bookshop!'))
            conn.commit()
            
            # Get the newly created user
            c.execute('SELECT * FROM users WHERE username = ?', (username,))
            user = c.fetchone()
            
            # Log the user in automatically
            session['user_id'] = user[0]
            session['username'] = user[1]
            
            flash('Registration successful! Welcome to Khit\'s Bookshop!', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            flash('An error occurred during registration.', 'danger')
            return render_template('register.html')
        finally:
            conn.close()
            
    return render_template('register.html')

@app.route('/add_to_cart/<int:book_id>', methods=['POST'])
def add_to_cart(book_id):
    if 'user_id' not in session:
        flash('Please login to add items to cart', 'danger')
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('bookshop.db')
    c = conn.cursor()
    
    # Check if book exists
    c.execute('SELECT * FROM books WHERE id = ?', (book_id,))
    book = c.fetchone()
    if not book:
        conn.close()
        flash('Book not found', 'danger')
        return redirect(url_for('index'))
    
    # Check if book is already in cart
    c.execute('SELECT * FROM cart WHERE user_id = ? AND book_id = ?', 
              (session['user_id'], book_id))
    cart_item = c.fetchone()
    
    if cart_item:
        # Update quantity
        c.execute('UPDATE cart SET quantity = quantity + 1 WHERE user_id = ? AND book_id = ?',
                 (session['user_id'], book_id))
    else:
        # Add new item to cart
        c.execute('INSERT INTO cart (user_id, book_id) VALUES (?, ?)',
                 (session['user_id'], book_id))
    
    conn.commit()
    conn.close()
    
    flash('Book added to cart!', 'success')
    return redirect(request.referrer or url_for('index'))

@app.route('/cart')
def view_cart():
    if 'user_id' not in session:
        flash('Please login to view your cart', 'danger')
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('bookshop.db')
    c = conn.cursor()
    
    # Get cart items with book details
    c.execute('''
        SELECT books.*, cart.quantity 
        FROM cart 
        JOIN books ON cart.book_id = books.id 
        WHERE cart.user_id = ?
    ''', (session['user_id'],))
    cart_items = c.fetchall()
    
    total = sum(item[3] * item[5] for item in cart_items)
    cart_count = get_cart_count()
    conn.close()
    return render_template('cart.html', cart_items=cart_items, total=total, session=session, cart_count=cart_count)

@app.route('/remove_from_cart/<int:book_id>', methods=['POST'])
def remove_from_cart(book_id):
    if 'user_id' not in session:
        flash('Please login first', 'danger')
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('bookshop.db')
    c = conn.cursor()
    c.execute('DELETE FROM cart WHERE user_id = ? AND book_id = ?',
              (session['user_id'], book_id))
    conn.commit()
    conn.close()
    
    flash('Item removed from cart', 'success')
    return redirect(url_for('view_cart'))

@app.route('/book_details')
def book_details():
    book_id = request.args.get('id', '')
    cart_count = get_cart_count()
    
    if not book_id:
        flash('Book ID is required', 'error')
        return redirect(url_for('books'))
        
    try:
        conn = sqlite3.connect('bookshop.db')
        c = conn.cursor()
        
        # Debug: Print the book_id and check WAF
        print(f"DEBUG: Original book_id = {book_id}")
        
        # WAF check - but allow MySQL-style comment bypass
        if waf_check(book_id):
            print(f"DEBUG: WAF blocked input: {book_id}")
            return "WAF blocked suspicious input", 403
        
        # SQLite doesn't support MySQL comments, so we need to remove them
        cleaned_id = book_id.replace("/*!50000", "").replace("*/", "")
        print(f"DEBUG: Cleaned book_id = {cleaned_id}")
        
        # Intentionally vulnerable to SQL injection
        query = f"SELECT id, title, author, price, image, description FROM books WHERE id = {cleaned_id}"
        print(f"DEBUG: Final Query = {query}")
        
        # Execute and get results
        try:
            c.execute(query)
            book = c.fetchone()
            print(f"DEBUG: Query Result = {book}")
        except sqlite3.OperationalError as sql_err:
            print(f"DEBUG: SQL Error = {sql_err}")
            return f"SQL Error: {str(sql_err)}", 500
            
        if not book:
            print("DEBUG: No book found")
            return "Book not found", 404
            
        return render_template('book_details.html', book=book, session=session, cart_count=cart_count)
        
    except sqlite3.Error as e:
        print(f"DEBUG: SQLite error: {str(e)}")
        return f"Database error: {str(e)}", 500
    except Exception as e:
        print(f"DEBUG: General error: {str(e)}")
        return f"Error: {str(e)}", 500
    finally:
        if conn:
            conn.close()

@app.route('/debug_db')
def debug_db():
    try:
        conn = sqlite3.connect('bookshop.db')
        c = conn.cursor()
        
        # Get admin's secret note
        c.execute('SELECT username, secret_note FROM users WHERE username=?', ('admin',))
        admin = c.fetchone()
        print(f"DEBUG: Admin data: {admin}")
        
        # Get first book
        c.execute('SELECT * FROM books WHERE id=1')
        book = c.fetchone()
        print(f"DEBUG: Book 1: {book}")
        
        return "Check server logs"
    except Exception as e:
        print(f"DEBUG Error: {str(e)}")
        return str(e)
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5005)
