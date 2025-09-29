from main import app, con
from flask_bcrypt import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    JWTManager, create_access_token, get_jwt_identity, get_jwt,
    verify_jwt_in_request, decode_token, jwt_required
)
from apscheduler.schedulers.background import BackgroundScheduler
import datetime
from flask import jsonify, request

# Configurar JWTManager — assegure que main.py define app.config['JWT_SECRET_KEY']
jwt = JWTManager(app)


# ✅ REMOVIDO: Importação duplicada

def agendar_exclusao_token(jti, horas):
    scheduler = BackgroundScheduler()
    horario_excluir = datetime.datetime.now() + datetime.timedelta(hours=horas)
    scheduler.add_job(func=excluir_token_expirado, args=(jti,), trigger='date', next_run_time=horario_excluir)
    scheduler.start()

def excluir_token_expirado(jti):
    cur = con.cursor()
    try:
        cur.execute("DELETE FROM BLACKLIST_TOKENS WHERE TOKEN = ?", (jti,))
        con.commit()
    except Exception:
        print("Erro em excluir_token_expirado")
        raise
    finally:
        try:
            cur.close()
        except Exception:
            pass


def generate_token(user_id):
    expires = datetime.timedelta(hours=3)
    access_token = create_access_token(identity=user_id, expires_delta=expires)
    return access_token


def remover_bearer(token):
    if token and token.startswith("Bearer "):
        return token[len("Bearer "):]
    else:
        return token


def is_token_revoked(jti):
    cur = con.cursor()
    try:
        cur.execute("SELECT 1 FROM BLACKLIST_TOKENS WHERE TOKEN = ?", (jti,))
        return cur.fetchone() is not None
    except Exception:
        print("Erro em is_token_revoked")
        raise
    finally:
        try:
            cur.close()
        except Exception:
            pass


@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload.get("jti")
    if not jti:
        return True
    return is_token_revoked(jti)


def verificar_user(tipo, trazer_pl):
    cur = con.cursor()
    try:
        token = request.headers.get('Authorization')
        if not token:
            return 1  # Token de autenticação necessário

        token = remover_bearer(token)

        try:
            verify_jwt_in_request(optional=True)
            payload_identity = get_jwt_identity()
            jwt_payload = get_jwt()
        except Exception as e:
            msg = str(e).lower()
            if 'expired' in msg or 'expired' in repr(e).lower():
                return 2  # Token expirado
            return 3  # Token inválido

        if not payload_identity:
            return 3

        id_logado = payload_identity

        if tipo == 2:
            cur.execute("SELECT 1 FROM USUARIOS WHERE ID_USUARIO = ? AND (TIPO = 2 OR TIPO = 3)", (id_logado,))
            biblio = cur.fetchone()
            if not biblio:
                return 4  # Nível Personal trainer requerido

        elif tipo == 3:
            cur.execute("SELECT 1 FROM USUARIOS WHERE ID_USUARIO = ? AND TIPO = 3", (id_logado,))
            admin = cur.fetchone()
            if not admin:
                return 5  # Nível Administrador requerido

        if trazer_pl:
            return {"id_usuario": id_logado, **jwt_payload}
        return None
    except Exception:
        print("Erro em verificar_user")
        raise
    finally:
        try:
            cur.close()
        except Exception:
            pass


def informar_verificacao(tipo=0, trazer_pl=False):
    verificacao = verificar_user(tipo, trazer_pl)
    if verificacao == 1:
        return jsonify({'mensagem': 'Token de autenticação necessário.', "verificacao": verificacao}), 401
    elif verificacao == 2:
        return jsonify({'mensagem': 'Token expirado.', "verificacao": verificacao}), 401
    elif verificacao == 3:
        return jsonify({'mensagem': 'Token inválido.', "verificacao": verificacao}), 401
    elif verificacao == 4:
        return jsonify({'mensagem': 'Nível Personal Trainer requerido.', "verificacao": verificacao}), 401
    elif verificacao == 5:
        return jsonify({'mensagem': 'Nível Administrador requerido.', "verificacao": verificacao}), 401
    else:
        if trazer_pl:
            return verificacao
        return None


global_contagem_erros = {}


@app.route('/login', methods=["POST"])
def logar():
    # Seu código de login está correto, mantém igual
    try:
        data = request.get_json()

        if not data:
            return jsonify({
                "message": "Dados não fornecidos",
                "error": "NO_DATA"
            }), 400

        email = data.get("email")
        senha = data.get("senha")

        if not email or not senha:
            return jsonify({
                "message": "Email e senha são obrigatórios",
                "error": "MISSING_FIELDS"
            }), 400

        email = email.lower().strip()

        cur = con.cursor()

        cur.execute("""
            SELECT SENHA, ID_USUARIO, NOME, EMAIL, TIPO, ATIVO 
            FROM USUARIOS 
            WHERE LOWER(EMAIL) = ?
        """, (email,))

        resultado = cur.fetchone()

        if not resultado:
            return jsonify({
                "message": "Email ou senha incorretos",
                "error": "INVALID_CREDENTIALS"
            }), 401

        senha_hash, id_user, nome, email_user, tipo, ativo = resultado

        if not ativo:
            return jsonify({
                "message": "Este usuário está inativo",
                "error": "USER_INACTIVE"
            }), 401

        if tipo not in [2, 3]:
            return jsonify({
                "message": "Acesso restrito a Personal Trainers e Administradores",
                "error": "INSUFFICIENT_PRIVILEGES"
            }), 403

        if not check_password_hash(senha_hash, senha):
            return jsonify({
                "message": "Email ou senha incorretos",
                "error": "INVALID_CREDENTIALS"
            }), 401

        access_token = generate_token(id_user)

        try:
            decoded = decode_token(access_token)
            jti = decoded.get("jti")
            if jti:
                agendar_exclusao_token(jti, 3)
        except Exception as e:
            print(f"Erro ao agendar exclusão token: {e}")

        id_user_str = f"usuario-{id_user}"
        if id_user_str in global_contagem_erros:
            del global_contagem_erros[id_user_str]

        return jsonify({
            "message": "Login realizado com sucesso!",
            "token": access_token,
            "nome": nome,
            "email": email_user,
            "tipo": tipo
        }), 200

    except Exception as e:
        print(f"Erro em logar: {e}")
        return jsonify({
            "message": "Erro interno do servidor",
            "error": "INTERNAL_ERROR"
        }), 500
    finally:
        try:
            cur.close()
        except Exception:
            pass


@app.route('/usuarios/cadastrar', methods=["POST"])
@jwt_required()  # ✅ Só Personal/Admin podem cadastrar
def cadastrar_usuario():
    # ✅ Verificar se é Personal ou Admin
    current_user_id = get_jwt_identity()
    cur = con.cursor()

    try:
        cur.execute("SELECT TIPO FROM USUARIOS WHERE ID_USUARIO = ?", (current_user_id,))
        resultado = cur.fetchone()

        if not resultado or resultado[0] not in [2, 3]:
            return jsonify({
                "message": "Acesso restrito a Personal Trainers e Administradores"
            }), 403

        user_logado_tipo = resultado[0]  # Tipo do usuário logado

    finally:
        cur.close()

    # ✅ DADOS DO BODY - Agora com campo 'tipo'
    data = request.get_json()
    nome = data.get('nome')
    senha1 = data.get('senha')
    cpf = data.get('cpf')
    email = data.get('email')
    tel = data.get('telefone')
    data_nasc = data.get('data_nascimento')
    desc_obj = data.get('descricao_objetivos')
    tipo_para_cadastrar = data.get('tipo', 1)  # ✅ Default = 1 (aluno)

    # ✅ VALIDAÇÃO DE PERMISSÃO POR TIPO
    if tipo_para_cadastrar == 2:  # Quer cadastrar Personal
        if user_logado_tipo != 3:  # Só Admin pode
            return jsonify({
                "message": "Apenas Administradores podem cadastrar Personal Trainers"
            }), 403

    elif tipo_para_cadastrar == 3:  # Quer cadastrar Admin
        if user_logado_tipo != 3:  # Só Admin pode
            return jsonify({
                "message": "Apenas Administradores podem cadastrar outros Administradores"
            }), 403

    # tipo_para_cadastrar == 1 (aluno) → Personal e Admin podem

    # ✅ VALIDAÇÕES (suas validações existentes...)
    if not all([nome, cpf, email, tel, data_nasc]):
        return jsonify({"message": "Todos os campos são obrigatórios"}), 400

    email = email.lower().strip()
    cpf1 = str(cpf)
    tel1 = str(tel)

    # Suas validações de CPF, telefone, senha, etc...
    # ... (código de validação existente) ...

    cur = con.cursor()
    try:
        # Verificar duplicatas (seu código existente)
        # ...

        # Hash da senha
        senha2 = generate_password_hash(senha1).decode('utf-8')

        # ✅ INSERIR COM O TIPO CORRETO
        cur.execute("""
            INSERT INTO USUARIOS (
                NOME, SENHA, CPF, EMAIL, TELEFONE, DATA_NASCIMENTO, 
                HISTORICO_MEDICO_RELEVANTE, DESCRICAO_MEDICAMENTOS, 
                DESCRICAO_LIMITACOES, TIPO, DESCRICAO_OBJETIVOS,
                DESCRICAO_TREINAMENTOS_ANTERIORES
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """, (nome, senha2, cpf1, email, tel1, data_nasc,
              his_med or "Nenhum", desc_med or "Nenhum", desc_lim or "Nenhum",
              tipo_para_cadastrar,  # ✅ TIPO DINÂMICO
              desc_obj or "Sem descrição", desc_tr or "Nenhuma"))

        con.commit()

        # ✅ MENSAGEM DINÂMICA POR TIPO
        tipo_texto = {
            1: "Aluno",
            2: "Personal Trainer",
            3: "Administrador"
        }

        return jsonify({
            "message": f"{tipo_texto[tipo_para_cadastrar]} cadastrado com sucesso!",
            "tipo": tipo_para_cadastrar,
            "tipo_texto": tipo_texto[tipo_para_cadastrar]
        }), 200

    except Exception as e:
        print(f"Erro em cadastrar_usuario: {e}")
        return jsonify({"message": "Erro interno do servidor"}), 500
    finally:
        try:
            cur.close()
        except Exception:
            pass

@app.route('/verificar-permissao', methods=['GET'])
@jwt_required()
def verificar_permissao():
    # Seu código está correto, mantém igual
    try:
        current_user_id = get_jwt_identity()

        cur = con.cursor()
        cur.execute("SELECT TIPO, NOME FROM USUARIOS WHERE ID_USUARIO = ?", (current_user_id,))
        resultado = cur.fetchone()

        if not resultado:
            return jsonify({
                "message": "Usuário não encontrado",
                "error": "USER_NOT_FOUND"
            }), 404

        tipo, nome = resultado

        return jsonify({
            "tipo": tipo,
            "nome": nome
        }), 200

    except Exception as e:
        print(f"Erro em verificar_permissao: {e}")
        return jsonify({
            "message": "Erro interno do servidor",
            "error": "INTERNAL_ERROR"
        }), 500
    finally:
        try:
            cur.close()
        except Exception:
            pass


@app.route('/logout', methods=["GET"])
def logout():
    # Seu código está correto, mantém igual
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"message": "Você já saiu de sua conta"}), 401
    token = remover_bearer(token)

    try:
        decoded = decode_token(token)
        jti = decoded.get("jti")
    except Exception:
        return jsonify({"message": "Token inválido."}), 401

    cur = con.cursor()
    try:
        cur.execute("SELECT 1 FROM BLACKLIST_TOKENS WHERE TOKEN = ?", (jti,))
        if cur.fetchone():
            return jsonify({"message": "Logout já feito com esse token"}), 401

        cur.execute("INSERT INTO BLACKLIST_TOKENS (TOKEN) VALUES (?)", (jti,))
        con.commit()

        agendar_exclusao_token(jti, 3)

        return jsonify({"message": "Logout bem-sucedido!"}), 200

    except Exception as e:
        return jsonify({"message": "Erro interno de servidor", "error": f"{e}"}), 500
    finally:
        cur.close()
