import sys, os, traceback
sys.path.insert(0, os.path.dirname(__file__))

import subprocess
import socket
import socket
import time
import ipaddress
import requests
from flask import Flask, request, jsonify, send_file
import google.generativeai as genai



app = Flask(__name__)

@app.errorhandler(500)
def internal_error(error):
    with open('/root/error.log', 'a') as f:
        f.write(f"[{time.ctime()}] Internal Server Error: {error}\n")
        f.write(traceback.format_exc())
        f.write("\n---\n")
    return jsonify({"error": "Internal Server Error. Check server logs for details."}), 500

# --- Konfigurasi Keamanan ---
RATE_LIMIT_SECONDS = 15  # Izinkan 1 permintaan per IP setiap 15 detik
REQUEST_TIMESTAMPS = {}

# --- Fungsi Bantuan Keamanan ---
def is_safe_target(target):
    """
    Memeriksa apakah target adalah alamat IP publik yang valid.
    Mencegah pemindaian terhadap alamat lokal, privat, atau broadcast.
    """
    try:
        # Coba resolve domain name jika bukan IP
        ip_str = socket.gethostbyname(target)
        ip = ipaddress.ip_address(ip_str)
        # Tolak jika alamat adalah tidak ditentukan (0.0.0.0)
        if ip.is_unspecified:
            return False, f"Pemindaian terhadap alamat IP tidak ditentukan ({ip_str}) tidak diizinkan."
        return True, None
    except socket.gaierror:
        return False, f"Gagal me-resolve domain '{target}'. Pastikan nama domain valid."
    except ValueError:
        return False, f"Target '{target}' bukan nama domain atau alamat IP yang valid."

# Route untuk menyajikan halaman HTML utama
@app.route('/')
def index():
    return send_file('/root/index.html')

# Route untuk API analisis
@app.route('/analyze', methods=['POST'])
def analyze():
    # --- Implementasi Rate Limiting ---
    client_ip = request.remote_addr
    current_time = time.time()
    last_request_time = REQUEST_TIMESTAMPS.get(client_ip)

    if last_request_time and (current_time - last_request_time) < RATE_LIMIT_SECONDS:
        return jsonify({"error": f"Terlalu banyak permintaan. Silakan tunggu {RATE_LIMIT_SECONDS} detik sebelum mencoba lagi."}), 429