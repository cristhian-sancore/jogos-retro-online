import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'data', 'database.db')

conn = sqlite3.connect(DB_PATH)
c = conn.cursor()

# Encontrar o admin que não tem email
c.execute('SELECT id, username FROM users WHERE is_admin = 1 AND (email IS NULL OR email = "")')
admins = c.fetchall()

if admins:
    for admin in admins:
        admin_id, username = admin
        default_email = f"{username}@admin.com"
        c.execute('UPDATE users SET email = ? WHERE id = ?', (default_email, admin_id))
        print(f"Admin '{username}' atualizado com o email: {default_email}")
    conn.commit()
else:
    print("Nenhum admin sem email encontrado.")

conn.close()
