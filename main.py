from flask import Flask
import fdb
from flask_cors import CORS

app = Flask(__name__)

# ✅ CORS CORRIGIDO - Permitir TODAS as origens
CORS(app, resources={r"/*": {"origins": "*"}})
# Ou específico para suas portas:
# CORS(app, resources={r"/*": {"origins": ["http://localhost:5500", "http://127.0.0.1:5500", "http://localhost:5173"]}})

app.config.from_pyfile('config.py')

host = app.config['DB_HOST']
database = app.config['DB_NAME']
user = app.config['DB_USER']
password = app.config['DB_PASSWORD']
debug = app.config['DEBUG']

try:
    con = fdb.connect(host=host, database=database, user=user, password=password)
    print(f"Conexão estabelecida com sucesso")
except Exception as e:
    print(f"Erro de conexão com o banco: {e}")

# ✅ ADICIONAR: Rota raiz para evitar 404
@app.route('/')
def home():
    return {'message': 'Atlas Gym API está funcionando!', 'version': '1.0'}

# ✅ ADICIONAR: Rota de teste
@app.route('/test')
def test():
    return {'status': 'OK', 'message': 'API funcionando perfeitamente'}

from view import *

if __name__ == '__main__':
    print("🚀 Iniciando Atlas Gym API...")
    print("📍 API disponível em: http://localhost:5000")
    print("🔧 Rotas disponíveis:")
    print("   - http://localhost:5000/")
    print("   - http://localhost:5000/test")
    print("   - http://localhost:5000/login")
    app.run(host='0.0.0.0', port=5000, debug=debug)
