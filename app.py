
import sys, os, traceback, subprocess, socket, time, ipaddress, requests
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# --- Konfigurasi Aplikasi ---
app = Flask(__name__)
# Kunci rahasia untuk session management. Di aplikasi nyata, ini harus kompleks dan disimpan sebagai environment variable.
app.config['SECRET_KEY'] = 'dev-secret-key' 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite' # Menggunakan SQLite
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- Model Database ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# --- Routes (Halaman) ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            flash('Username sudah ada', 'danger')
            return redirect(url_for('register'))

        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registrasi berhasil! Silakan login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('dashboard'))
        else:
            flash('Username atau password salah', 'danger')
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# --- API (Fitur Asli) ---

# Konfigurasi Keamanan API
RATE_LIMIT_SECONDS = 15
REQUEST_TIMESTAMPS = {}

def is_safe_target(target):
    try:
        ip_str = socket.gethostbyname(target)
        ip = ipaddress.ip_address(ip_str)
        if ip.is_unspecified:
            return False, f"Pemindaian terhadap alamat IP tidak ditentukan ({ip_str}) tidak diizinkan."
        return True, None
    except socket.gaierror:
        return False, f"Gagal me-resolve domain '{target}'. Pastikan nama domain valid."
    except ValueError:
        return False, f"Target '{target}' bukan nama domain atau alamat IP yang valid."

@app.route('/analyze', methods=['POST'])
def analyze():
    # Cek apakah user sudah login
    if 'user_id' not in session:
        return jsonify({"error": "Akses ditolak. Silakan login terlebih dahulu."}), 403

    # Rate Limiting per user
    user_id = session['user_id']
    current_time = time.time()
    last_request_time = REQUEST_TIMESTAMPS.get(user_id)

    if last_request_time and (current_time - last_request_time) < RATE_LIMIT_SECONDS:
        return jsonify({"error": f"Terlalu banyak permintaan. Silakan tunggu {RATE_LIMIT_SECONDS} detik."}), 429

    REQUEST_TIMESTAMPS[user_id] = current_time

    data = request.get_json()
    target = data.get('target')

    if not target:
        return jsonify({"error": "Target tidak boleh kosong"}), 400

    safe, message = is_safe_target(target)
    if not safe:
        return jsonify({"error": message}), 400

    try:
        # Menjalankan traceroute dan menangkap output
        result = subprocess.check_output(['traceroute', '-w', '2', '-q', '1', target], stderr=subprocess.STDOUT, text=True)
        return jsonify({"target": target, "result": result})
    except subprocess.CalledProcessError as e:
        return jsonify({"error": f"Perintah traceroute gagal: {e.output}"}), 500
    except FileNotFoundError:
        return jsonify({"error": "Perintah 'traceroute' tidak ditemukan. Pastikan sudah terinstall di server."}), 500

# --- Error Handling & Inisialisasi DB ---

@app.errorhandler(500)
def internal_error(error):
    # Log ke stderr (praktik terbaik untuk container)
    print(f"[{time.ctime()}] Internal Server Error: {error}", file=sys.stderr)
    traceback.print_exc()
    return jsonify({"error": "Internal Server Error. Hubungi administrator."}), 500

# Perintah untuk inisialisasi database
@app.cli.command('init-db')
def init_db_command():
    """Membuat tabel database baru."""
    db.create_all()
    print('Database telah diinisialisasi.')

if __name__ == '__main__':
    # Perhatian: app.run() hanya untuk development.
    # Untuk produksi, gunakan Gunicorn: gunicorn --bind 0.0.0.0:5000 app:app
    app.run(debug=True)
