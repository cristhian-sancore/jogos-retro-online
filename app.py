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
AVATARS_DIR = os.path.join(BASE_DIR, 'static', 'avatars')
DATA_DIR = os.path.join(BASE_DIR, 'data')
DB_PATH = os.path.join(DATA_DIR, 'database.db')

# Garante que os diretórios existem
os.makedirs(ROMS_DIR, exist_ok=True)
os.makedirs(SAVES_DIR, exist_ok=True)
os.makedirs(COVERS_DIR, exist_ok=True)
os.makedirs(AVATARS_DIR, exist_ok=True)
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
                  is_admin BOOLEAN DEFAULT 0,
                  is_banned BOOLEAN DEFAULT 0)''')
    
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
    
    # Tabela de Favoritos
    c.execute('''CREATE TABLE IF NOT EXISTS favorites
                 (user_id INTEGER,
                  game_id INTEGER,
                  FOREIGN KEY (user_id) REFERENCES users (id),
                  FOREIGN KEY (game_id) REFERENCES games (id),
                  UNIQUE(user_id, game_id))''')
                  
    # Tabela de Reviews
    c.execute('''CREATE TABLE IF NOT EXISTS reviews
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER,
                  game_id INTEGER,
                  rating INTEGER,
                  comment TEXT,
                  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (user_id) REFERENCES users (id),
                  FOREIGN KEY (game_id) REFERENCES games (id),
                  UNIQUE(user_id, game_id))''')
    
    # Migrações seguras caso a tabela já exista sem as colunas novas
    try:
        c.execute('ALTER TABLE achievements ADD COLUMN user_id INTEGER')
    except sqlite3.OperationalError:
        pass # Coluna já existe
    try:
        c.execute('ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT 0')
    except sqlite3.OperationalError:
        pass # Coluna já existe

    try:
        c.execute('ALTER TABLE users ADD COLUMN is_banned BOOLEAN DEFAULT 0')
    except sqlite3.OperationalError:
        pass # Coluna já existe

    try: c.execute('ALTER TABLE users ADD COLUMN full_name TEXT')
    except sqlite3.OperationalError: pass
    
    try: c.execute('ALTER TABLE users ADD COLUMN birthdate TEXT')
    except sqlite3.OperationalError: pass
    
    try: c.execute('ALTER TABLE users ADD COLUMN email TEXT')
    except sqlite3.OperationalError: pass
    
    try: c.execute('ALTER TABLE users ADD COLUMN avatar_filename TEXT')
    except sqlite3.OperationalError: pass

    # Auto-correção para administradores antigos que não tinham email (usam username@admin.com temporariamente)
    try:
        c.execute('UPDATE users SET email = username || "@admin.com" WHERE is_admin = 1 AND (email IS NULL OR email = "")')
    except sqlite3.OperationalError:
        pass

    conn.commit()
    conn.close()

init_db()

def get_games_list(q=None, favs_only=False, user_id=None):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    query = '''
        SELECT games.id, games.title, games.filename, games.cover_filename,
               IFNULL(AVG(reviews.rating), 0) as avg_rating,
               COUNT(reviews.id) as review_count
        FROM games
        LEFT JOIN reviews ON games.id = reviews.game_id
    '''
    params = []
    
    if favs_only and user_id:
        query += ' INNER JOIN favorites ON games.id = favorites.game_id WHERE favorites.user_id = ?'
        params.append(user_id)
        if q:
            query += ' AND games.title LIKE ?'
            params.append(f'%{q}%')
    elif q:
        query += ' WHERE games.title LIKE ?'
        params.append(f'%{q}%')
        
    query += ' GROUP BY games.id ORDER BY games.title'
    
    c.execute(query, params)
    games_db = c.fetchall()
    conn.close()
    
    games = []
    for g in games_db:
        games.append({
            'id': g[0],
            'title': g[1],
            'filename': g[2],
            'cover_filename': g[3],
            'avg_rating': round(g[4], 1),
            'review_count': g[5]
        })
    return games

# HOOK GLOBAL PARA VERIFICAR BANIMENTO
@app.before_request
def check_banned():
    # Ignorar rotas de arquivos estáticos e login/registro para não dar loop infinito
    if request.endpoint in ['static', 'login', 'register']:
        return

    if 'user_id' in session:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT is_banned FROM users WHERE id = ?', (session['user_id'],))
        row = c.fetchone()
        conn.close()
        
        if row and row[0]:
            session.clear()
            flash('Sua conta foi banida pelo administrador.')
            return redirect(url_for('login'))

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
        email = request.form['email']
        password = request.form['password']
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT id, password, username, avatar_filename FROM users WHERE email = ?', (email,))
        user = c.fetchone()
        conn.close()
        
        if user and check_password_hash(user[1], password):
            session['user_id'] = user[0]
            session['username'] = user[2]
            session['avatar'] = user[3] if len(user) > 3 else None
            return redirect(url_for('index'))
        else:
            flash('E-mail ou senha incorretos.')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form.get('full_name')
        birthdate = request.form.get('birthdate')
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        avatar_file = request.files.get('avatar')
        
        avatar_filename = None
        if avatar_file and avatar_file.filename:
            avatar_filename = secure_filename(f"{username}_{avatar_file.filename}")
            avatar_file.save(os.path.join(AVATARS_DIR, avatar_filename))
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        # O primeiro usuário se torna o Admin
        c.execute('SELECT COUNT(*) FROM users')
        count = c.fetchone()[0]
        is_admin = 1 if count == 0 else 0

        try:
            hashed_pw = generate_password_hash(password)
            c.execute('''INSERT INTO users 
                         (username, password, is_admin, full_name, birthdate, email, avatar_filename) 
                         VALUES (?, ?, ?, ?, ?, ?, ?)''', 
                      (username, hashed_pw, is_admin, full_name, birthdate, email, avatar_filename))
            conn.commit()
            conn.close()
            flash('Conta criada com sucesso! Faça login.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            conn.close()
            flash('E-mail ou nome de usuário já está em uso.')
            
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ROTAS DE PERFIL DO USUÁRIO
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    user_id = session['user_id']
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    if request.method == 'POST':
        full_name = request.form.get('full_name')
        email = request.form.get('email')
        password = request.form.get('password')
        avatar_file = request.files.get('avatar')
        
        c.execute('SELECT avatar_filename, username FROM users WHERE id = ?', (user_id,))
        row = c.fetchone()
        current_avatar = row[0]
        username = row[1]
        
        new_avatar_filename = current_avatar
        if avatar_file and avatar_file.filename:
            new_avatar_filename = secure_filename(f"{username}_{avatar_file.filename}")
            avatar_file.save(os.path.join(AVATARS_DIR, new_avatar_filename))
            session['avatar'] = new_avatar_filename
            
        if password: # Se enviou nova senha
            hashed_pw = generate_password_hash(password)
            c.execute('UPDATE users SET full_name = ?, email = ?, password = ?, avatar_filename = ? WHERE id = ?',
                      (full_name, email, hashed_pw, new_avatar_filename, user_id))
        else:
            c.execute('UPDATE users SET full_name = ?, email = ?, avatar_filename = ? WHERE id = ?',
                      (full_name, email, new_avatar_filename, user_id))
            
        try:
            conn.commit()
            flash("Perfil atualizado com sucesso!")
        except sqlite3.IntegrityError:
            flash("Este e-mail já está em uso por outra conta.")
            
        return redirect(url_for('profile'))
        
    # GET: Carregar dados
    c.execute('SELECT username, full_name, email, birthdate, avatar_filename FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()
    
    # Carregar conquistas (todas)
    c.execute('SELECT game, achievement_name, timestamp FROM achievements WHERE user_id = ? ORDER BY timestamp DESC', (user_id,))
    achievements = c.fetchall()
    conn.close()
    
    user_dict = {
        'username': user[0],
        'full_name': user[1],
        'email': user[2],
        'birthdate': user[3],
        'avatar_filename': user[4]
    }
    
    # Carregar saves
    user_saves = []
    prefix = f"{user_id}_"
    if os.path.exists(SAVES_DIR):
        for f in os.listdir(SAVES_DIR):
            if f.startswith(prefix):
                stat = os.stat(os.path.join(SAVES_DIR, f))
                user_saves.append({
                    'filename': f,
                    'game_name': f.replace(prefix, '').replace('.srm', ''),
                    'size': round(stat.st_size / 1024, 2), # KB
                    'date': stat.st_mtime
                })
    # Ordenar saves por data (mais recentes primeiro)
    user_saves.sort(key=lambda x: x['date'], reverse=True)
    
    return render_template('profile.html', user=user_dict, achievements=achievements, saves=user_saves)

@app.route('/profile/delete_save/<filename>', methods=['POST'])
def delete_save(filename):
    if 'user_id' not in session:
        abort(401)
        
    # Segurança: garantir que o usuário só apaga o próprio save
    if not filename.startswith(f"{session['user_id']}_"):
        abort(403)
        
    try:
        os.remove(os.path.join(SAVES_DIR, filename))
        flash("Save removido da nuvem.")
    except OSError:
        flash("Erro ao remover o save.")
        
    return redirect(url_for('profile'))

# ROTAS DO PAINEL ADMIN
@app.route('/admin')
@admin_required
def admin():
    games = get_games_list()
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    c.execute('SELECT COUNT(*) FROM users')
    total_users = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM games')
    total_games = c.fetchone()[0]
    
    try:
        c.execute('SELECT COUNT(*) FROM reviews')
        total_reviews = c.fetchone()[0]
    except sqlite3.OperationalError:
        total_reviews = 0
        
    c.execute('SELECT COUNT(*) FROM achievements')
    total_achievements = c.fetchone()[0]
    
    conn.close()
    
    stats = {
        'total_users': total_users,
        'total_games': total_games,
        'total_reviews': total_reviews,
        'total_achievements': total_achievements
    }
    
    return render_template('admin.html', games=games, stats=stats)

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

@app.route('/admin/edit/<int:game_id>', methods=['GET', 'POST'])
@admin_required
def admin_edit(game_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    if request.method == 'POST':
        title = request.form.get('title')
        rom_file = request.files.get('rom')
        cover_file = request.files.get('cover')
        
        c.execute('SELECT filename, cover_filename FROM games WHERE id = ?', (game_id,))
        row = c.fetchone()
        
        if not title:
            flash("O título é obrigatório!")
            return redirect(url_for('admin_edit', game_id=game_id))
            
        new_rom_filename = row[0]
        new_cover_filename = row[1]
        
        if rom_file and rom_file.filename:
            new_rom_filename = secure_filename(rom_file.filename)
            rom_file.save(os.path.join(ROMS_DIR, new_rom_filename))
            # Apagar a rom antiga se for diferente
            if row[0] != new_rom_filename:
                try: os.remove(os.path.join(ROMS_DIR, row[0]))
                except OSError: pass
                
        if cover_file and cover_file.filename:
            new_cover_filename = secure_filename(cover_file.filename)
            cover_file.save(os.path.join(COVERS_DIR, new_cover_filename))
            # Apagar a capa antiga se for diferente
            if row[1] != new_cover_filename:
                try: os.remove(os.path.join(COVERS_DIR, row[1]))
                except OSError: pass
                
        c.execute('UPDATE games SET title = ?, filename = ?, cover_filename = ? WHERE id = ?',
                  (title, new_rom_filename, new_cover_filename, game_id))
        conn.commit()
        conn.close()
        
        flash("Jogo atualizado com sucesso!")
        return redirect(url_for('admin'))
        
    else:
        c.execute('SELECT id, title, filename, cover_filename FROM games WHERE id = ?', (game_id,))
        game = c.fetchone()
        conn.close()
        if not game:
            abort(404)
            
        game_dict = {
            'id': game[0],
            'title': game[1],
            'filename': game[2],
            'cover_filename': game[3]
        }
        return render_template('admin_edit.html', game=game_dict)

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

@app.route('/admin/users')
@admin_required
def admin_users():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, username, is_admin, is_banned FROM users ORDER BY username')
    users_db = c.fetchall()
    conn.close()
    
    users = []
    for u in users_db:
        users.append({
            'id': u[0],
            'username': u[1],
            'is_admin': u[2],
            'is_banned': u[3]
        })
    return render_template('admin_users.html', users=users)

@app.route('/admin/users/ban/<int:target_user_id>', methods=['POST'])
@admin_required
def admin_toggle_ban(target_user_id):
    # Previne que o admin se bana
    if target_user_id == session['user_id']:
        flash("Você não pode banir a si mesmo!")
        return redirect(url_for('admin_users'))
        
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Verifica o status atual
    c.execute('SELECT is_banned FROM users WHERE id = ?', (target_user_id,))
    row = c.fetchone()
    if row:
        new_status = 0 if row[0] else 1
        c.execute('UPDATE users SET is_banned = ? WHERE id = ?', (new_status, target_user_id))
        conn.commit()
        if new_status:
            flash("Usuário banido com sucesso.")
        else:
            flash("Usuário desbanido com sucesso.")
            
    conn.close()
    return redirect(url_for('admin_users'))

# ROTAS DO PAINEL E JOGOS
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    q = request.args.get('q', '')
    favs_only = request.args.get('favs_only') == '1'
    user_id = session['user_id']
    
    games = get_games_list(q=q, favs_only=favs_only, user_id=user_id)
    
    # Pega as conquistas do usuário logado e favoritos
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT game, achievement_name FROM achievements WHERE user_id = ? ORDER BY timestamp DESC LIMIT 10', (user_id,))
    user_achievements = c.fetchall()
    
    c.execute('SELECT game_id FROM favorites WHERE user_id = ?', (user_id,))
    fav_rows = c.fetchall()
    favorite_game_ids = [row[0] for row in fav_rows]
    
    # Verifica se é admin para mostrar o botão do painel
    c.execute('SELECT is_admin FROM users WHERE id = ?', (user_id,))
    row = c.fetchone()
    is_admin = bool(row[0]) if row else False
    
    conn.close()
    
    avatar = session.get('avatar')
    
    return render_template('index.html', games=games, achievements=user_achievements, username=session['username'], is_admin=is_admin, avatar=avatar, favorite_game_ids=favorite_game_ids, q=q, favs_only=favs_only)

@app.route('/api/favorite/<int:game_id>', methods=['POST'])
def toggle_favorite(game_id):
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = session['user_id']
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    c.execute('SELECT 1 FROM favorites WHERE user_id = ? AND game_id = ?', (user_id, game_id))
    exists = c.fetchone()
    
    is_favorite = False
    if exists:
        c.execute('DELETE FROM favorites WHERE user_id = ? AND game_id = ?', (user_id, game_id))
    else:
        c.execute('INSERT INTO favorites (user_id, game_id) VALUES (?, ?)', (user_id, game_id))
        is_favorite = True
        
    conn.commit()
    conn.close()
    
    return jsonify({"success": True, "is_favorite": is_favorite})

@app.route('/play/<filename>')
def play(filename):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    if not os.path.exists(os.path.join(ROMS_DIR, filename)):
        abort(404)
        
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, title FROM games WHERE filename = ?', (filename,))
    game = c.fetchone()
    if not game:
        conn.close()
        abort(404)
        
    game_id, game_title = game
    
    # Pega os reviews desse jogo
    c.execute('''
        SELECT users.username, users.avatar_filename, reviews.rating, reviews.comment, reviews.timestamp 
        FROM reviews 
        JOIN users ON reviews.user_id = users.id 
        WHERE reviews.game_id = ? 
        ORDER BY reviews.timestamp DESC
    ''', (game_id,))
    reviews_db = c.fetchall()
    
    # Verifica se o usuário atual já fez review
    c.execute('SELECT rating, comment FROM reviews WHERE game_id = ? AND user_id = ?', (game_id, session['user_id']))
    user_review = c.fetchone()
    
    conn.close()
    
    reviews = []
    for r in reviews_db:
        reviews.append({
            'username': r[0],
            'avatar_filename': r[1],
            'rating': r[2],
            'comment': r[3],
            'timestamp': r[4]
        })
        
    netplay_url = os.environ.get('NETPLAY_URL', 'ws://' + request.host.split(':')[0] + ':3000/')
    return render_template('play.html', filename=filename, name=game_title, game_id=game_id, user_id=session['user_id'], netplay_url=netplay_url, reviews=reviews, user_review=user_review)

@app.route('/api/review/<int:game_id>', methods=['POST'])
def add_review(game_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    rating = int(request.form.get('rating', 0))
    comment = request.form.get('comment', '').strip()
    user_id = session['user_id']
    
    if rating < 1 or rating > 5:
        flash("Selecione uma nota válida (1 a 5 estrelas).")
        return redirect(request.referrer)
        
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        c.execute('INSERT INTO reviews (user_id, game_id, rating, comment) VALUES (?, ?, ?, ?)', (user_id, game_id, rating, comment))
        conn.commit()
        flash("Sua avaliação foi enviada com sucesso!")
    except sqlite3.IntegrityError:
        flash("Você já avaliou este jogo.")
        
    conn.close()
    return redirect(request.referrer)


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
