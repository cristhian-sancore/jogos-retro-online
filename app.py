import os
import base64
from io import BytesIO
import sqlite3
from flask import Flask, render_template, send_from_directory, abort, request, jsonify, session, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from PIL import Image
import pytesseract
import secrets

app = Flask(__name__)
# Chave secreta segura gerada aleatoriamente no boot
app.secret_key = secrets.token_hex(16) 

# Configurações
BASE_DIR = os.path.dirname(os.path.abspath(__name__))
ROMS_DIR = os.path.join(BASE_DIR, 'roms')
SAVES_DIR = os.path.join(BASE_DIR, 'saves')
COVERS_DIR = os.path.join(BASE_DIR, 'static', 'covers')
DATA_DIR = os.path.join(BASE_DIR, 'data')
DB_PATH = os.path.join(DATA_DIR, 'database.db')

# Garante que os diretórios existem
os.makedirs(ROMS_DIR, exist_ok=True)
os.makedirs(SAVES_DIR, exist_ok=True)
os.makedirs(COVERS_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

# Inicializa o banco de dados
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Tabela de Usuários (atualizada com is_admin)
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL,
                  is_admin BOOLEAN DEFAULT 0)''')
    
    # Tabela de Conquistas
    c.execute('''CREATE TABLE IF NOT EXISTS achievements
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER,
                  game TEXT,
                  achievement_name TEXT,
                  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (user_id) REFERENCES users (id))''')

    # Nova Tabela de Jogos (Capa e Título)
    c.execute('''CREATE TABLE IF NOT EXISTS games
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  title TEXT NOT NULL,
                  filename TEXT NOT NULL,
                  cover_filename TEXT NOT NULL)''')
    
    # Migrações seguras caso a tabela já exista sem as colunas novas
    try:
        c.execute('ALTER TABLE achievements ADD COLUMN user_id INTEGER')
    except sqlite3.OperationalError:
        pass # Coluna já existe
    try:
        c.execute('ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT 0')
    except sqlite3.OperationalError:
        pass # Coluna já existe

    conn.commit()
    conn.close()

init_db()

def get_games_list():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, title, filename, cover_filename FROM games ORDER BY title')
    games_db = c.fetchall()
    conn.close()
    
    games = []
    for g in games_db:
        games.append({
            'id': g[0],
            'title': g[1],
            'filename': g[2],
            'cover_filename': g[3]
        })
    return games

# DECORADOR SUPER ADMIN
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT is_admin FROM users WHERE id = ?', (session['user_id'],))
        row = c.fetchone()
        conn.close()
        if not row or not row[0]:
            abort(403) # Proibido
        return f(*args, **kwargs)
    return decorated_function

# ROTAS DE AUTENTICAÇÃO
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT id, password FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()
        
        if user and check_password_hash(user[1], password):
            session['user_id'] = user[0]
            session['username'] = username
            return redirect(url_for('index'))
        else:
            flash('Usuário ou senha incorretos.')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        # O primeiro usuário se torna o Admin
        c.execute('SELECT COUNT(*) FROM users')
        count = c.fetchone()[0]
        is_admin = 1 if count == 0 else 0

        try:
            hashed_pw = generate_password_hash(password)
            c.execute('INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)', (username, hashed_pw, is_admin))
            conn.commit()
            conn.close()
            flash('Conta criada com sucesso! Faça login.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            conn.close()
            flash('Esse nome de usuário já existe.')
            
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ROTAS DO PAINEL ADMIN
@app.route('/admin')
@admin_required
def admin():
    games = get_games_list()
    return render_template('admin.html', games=games)

@app.route('/admin/upload', methods=['POST'])
@admin_required
def admin_upload():
    title = request.form.get('title')
    rom_file = request.files.get('rom')
    cover_file = request.files.get('cover')

    if not title or not rom_file or not cover_file:
        flash("Todos os campos são obrigatórios!")
        return redirect(url_for('admin'))
        
    rom_filename = secure_filename(rom_file.filename)
    cover_filename = secure_filename(cover_file.filename)
    
    # Salvar arquivos
    rom_file.save(os.path.join(ROMS_DIR, rom_filename))
    cover_file.save(os.path.join(COVERS_DIR, cover_filename))
    
    # Salvar no BD
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('INSERT INTO games (title, filename, cover_filename) VALUES (?, ?, ?)', 
              (title, rom_filename, cover_filename))
    conn.commit()
    conn.close()
    
    flash("Jogo adicionado com sucesso!")
    return redirect(url_for('admin'))

@app.route('/admin/delete/<int:game_id>', methods=['POST'])
@admin_required
def admin_delete(game_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT filename, cover_filename FROM games WHERE id = ?', (game_id,))
    row = c.fetchone()
    if row:
        try:
            os.remove(os.path.join(ROMS_DIR, row[0]))
        except OSError: pass
        try:
            os.remove(os.path.join(COVERS_DIR, row[1]))
        except OSError: pass
        c.execute('DELETE FROM games WHERE id = ?', (game_id,))
        conn.commit()
    conn.close()
    flash("Jogo removido.")
    return redirect(url_for('admin'))

# ROTAS DO PAINEL E JOGOS
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    games = get_games_list()
    # Pega as conquistas do usuário logado
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT game, achievement_name FROM achievements WHERE user_id = ? ORDER BY timestamp DESC LIMIT 10', (session['user_id'],))
    user_achievements = c.fetchall()
    
    # Verifica se é admin para mostrar o botão do painel
    c.execute('SELECT is_admin FROM users WHERE id = ?', (session['user_id'],))
    row = c.fetchone()
    is_admin = bool(row[0]) if row else False
    
    conn.close()
    
    return render_template('index.html', games=games, achievements=user_achievements, username=session['username'], is_admin=is_admin)

@app.route('/play/<filename>')
def play(filename):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    if not os.path.exists(os.path.join(ROMS_DIR, filename)):
        abort(404)
        
    name = os.path.splitext(filename)[0]
    netplay_url = os.environ.get('NETPLAY_URL', 'ws://' + request.host.split(':')[0] + ':3000/')
    return render_template('play.html', filename=filename, name=name, user_id=session['user_id'], netplay_url=netplay_url)


# ARQUIVOS ESTÁTICOS E SAVES
@app.route('/roms/<filename>')
def download_rom(filename):
    if 'user_id' not in session: abort(403)
    return send_from_directory(ROMS_DIR, filename)

@app.route('/saves/<filename>')
def download_save(filename):
    if 'user_id' not in session: abort(403)
    # Segurança: Garante que o usuário só baixa o próprio save
    if not filename.startswith(f"{session['user_id']}_"):
        abort(403)
    return send_from_directory(SAVES_DIR, filename)

@app.route('/api/save', methods=['POST'])
def save_game():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
        
    game_name = request.form.get('game_name')
    save_file = request.files.get('save_data')
    
    if not game_name or not save_file:
        return jsonify({"error": "Missing data"}), 400
        
    save_filename = f"{session['user_id']}_{game_name}.srm"
    save_path = os.path.join(SAVES_DIR, save_filename)
    save_file.save(save_path)
    print(f"Save recebido com sucesso na nuvem: {save_filename}")
    
    return jsonify({"success": True})


# SISTEMA DE CONQUISTAS (OCR)
@app.route('/api/check_achievement', methods=['POST'])
def check_achievement():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json
    game_name = data.get('game_name')
    image_data = data.get('image_data')

    if not image_data:
        return jsonify({"error": "No image data"}), 400

    try:
        header, encoded = image_data.split(',', 1)
        image_bytes = base64.b64decode(encoded)
        image = Image.open(BytesIO(image_bytes))

        # Analisar a imagem com Tesseract OCR
        text = pytesseract.image_to_string(image).upper()

        achievement_unlocked = None
        keywords = ["CONGRATULATIONS", "WIN", "VICTORY", "THE END", "THANK YOU FOR PLAYING"]
        
        for word in keywords:
            if word in text:
                achievement_unlocked = "Terminou o Jogo!"
                break
        
        if achievement_unlocked:
            user_id = session['user_id']
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute('SELECT 1 FROM achievements WHERE user_id=? AND game=? AND achievement_name=?', 
                     (user_id, game_name, achievement_unlocked))
            exists = c.fetchone()
            
            if not exists:
                c.execute('INSERT INTO achievements (user_id, game, achievement_name) VALUES (?, ?, ?)', 
                         (user_id, game_name, achievement_unlocked))
                conn.commit()
                conn.close()
                return jsonify({"unlocked": True, "achievement": achievement_unlocked})
            conn.close()

        return jsonify({"unlocked": False})

    except Exception as e:
        print(f"Erro na análise de OCR: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=5000)
