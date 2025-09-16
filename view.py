from main import app, con
from flask_bcrypt import generate_password_hash, check_password_hash
import jwt
import config
import datetime
from flask import jsonify, request

# Funções globais
# Funções de token
senha_secreta = app.config['SECRET_KEY']

def generate_token(user_id):
    payload = {
        "id_usuario": user_id,
        'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=3)
    }
    token = jwt.encode(payload, senha_secreta, algorithm='HS256')
    return token


def remover_bearer(token):
    if token.startswith("Bearer "):
        return token[len("Bearer "):]
    else:
        return token


def verificar_user(tipo, trazer_pl):
    cur = con.cursor()
    try:
        token = request.headers.get('Authorization')
        if not token:
            return 1  # Token de autenticação necessário

        token = remover_bearer(token)
        try:
            payload = jwt.decode(token, senha_secreta, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return 2  # Token expirado
        except jwt.InvalidTokenError:
            return 3  # Token inválido

        id_logado = payload["id_usuario"]

        if tipo == 2:
            cur.execute("SELECT 1 FROM USUARIOS WHERE ID_USUARIO = ? AND (TIPO = 2 OR TIPO = 3)", (id_logado,))
            biblio = cur.fetchone()
            if not biblio:
                return 4  # Nível bibliotecário requerido

        elif tipo == 3:
            cur.execute("SELECT 1 FROM USUARIOS WHERE ID_USUARIO = ? AND TIPO = 3", (id_logado,))
            admin = cur.fetchone()
            if not admin:
                return 5  # Nível Administrador requerido

        if trazer_pl:
            return payload
        pass
    except Exception:
        print("Erro em verificar_user")
        raise
    finally:
        cur.close()


def informar_verificacao(tipo=0, trazer_pl=False):
    verificacao = verificar_user(tipo, trazer_pl)
    if verificacao == 1:
        return jsonify({'mensagem': 'Token de autenticação necessário.', "verificacao": verificacao}), 401
    elif verificacao == 2:
        return jsonify({'mensagem': 'Token expirado.', "verificacao": verificacao}), 401
    elif verificacao == 3:
        return jsonify({'mensagem': 'Token inválido.', "verificacao": verificacao}), 401
    elif verificacao == 4:
        return jsonify({'mensagem': 'Nível Bibliotecário requerido.', "verificacao": verificacao}), 401
    elif verificacao == 5:
        return jsonify({'mensagem': 'Nível Administrador requerido.', "verificacao": verificacao}), 401
    else:
        if trazer_pl:
            return verificacao
        return None

@app.route("/usuarios/cadastrar", methods=["POST"])
def cadastrar_normal():
    data = request.get_json()
    nome = data.get('nome')
    cpf = data.get('cpf')
    email = data.get('email')
    tel = data.get('telefone')
    data_nasc = data.get('data_nascimento')
    genero = data.get('genero')
    altura = data.get('altura')
    peso = data.get('peso')
    his_med = data.get('historico_medico_relevante')
    desc_med = data.get('descricao_medicamentos')
    desc_lim = data.get('descricao_limitacoes')
    tipo = data.get('tipo')
    desc_obj = data.get('descricao_objetivos')
    desc_tr = data.get('descricao_treinamentos_anteriores')

    if not all([cpf, email, tel, data_nasc, genero, altura, peso, his_med, desc_med, desc_lim, tipo, desc_obj, desc_tr]):
        return jsonify({"message": "Todos os campos são obrigatórios"}), 400

    # Verificações de comprimento de dados
    if len(nome) > 895:
        return jsonify({"message": "Nome grande demais, o limite é 895 caracteres"}), 401
    if len(cpf) != 11:
        return jsonify({"message": "O CPF precisa ter 11 dígitos"}), 401
    if len(tel) != 13:
        return jsonify({"message": """O telefone precisa ser enviado
         em 13 dígitos exemplo: +55 (18) 12345-1234 = 5518123451234"""}), 401
    if len(genero) > 100:
        return jsonify({"message": "Limite de dígitos de gênero excedido (100)"}), 401

    # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!

    cur = con.cursor()
    try:
        # Verificações a partir do banco de dados
        # Verificações de duplicatas
        cur.execute("SELECT CPF FROM USUARIOS WHERE CPF = ?", (cpf, ))
        resposta = cur.fetchone()
        if resposta[0] == cpf:
            return jsonify({"message": "CPF já cadastrado"}), 401

        cur.execute("SELECT EMAIL FROM USUARIOS WHERE EMAIL = ?", (email,))
        resposta = cur.fetchone()
        if resposta[0] == email:
            return jsonify({"message": "Email já cadastrado"}), 401

        cur.execute("SELECT TELEFONE FROM USUARIOS WHERE EMAIL = ?", (tel,))
        resposta = cur.fetchone()
        if resposta[0] == tel:
            return jsonify({"message": "Telefone já cadastrado"}), 401

    except Exception as e:
        print("Erro em /usuarios/cadastrar")
        return jsonify({"message": "Erro em /usuarios/cadastrar", "erro": f"{e}"}), 500
    finally:
        cur.close()