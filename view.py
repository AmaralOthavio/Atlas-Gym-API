from main import app, con
from flask_bcrypt import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    JWTManager, create_access_token, get_jwt_identity, get_jwt,
    verify_jwt_in_request, decode_token
)
from apscheduler.schedulers.background import BackgroundScheduler
import datetime
from flask import jsonify, request

# Configurar JWTManager — assegure que main.py define app.config['JWT_SECRET_KEY']
jwt = JWTManager(app)

# Funções globais
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
            # verifica token se presente; optional=True evita abort automático quando não houver token
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
        return jsonify({'mensagem': 'Nível Bibliotecário requerido.', "verificacao": verificacao}), 401
    elif verificacao == 5:
        return jsonify({'mensagem': 'Nível Administrador requerido.', "verificacao": verificacao}), 401
    else:
        if trazer_pl:
            return verificacao
        return None

@app.route('/usuarios/cadastrar', methods=["POST"])
def cadastrar_normal():
    data = request.get_json()
    nome = data.get('nome')
    senha1 = data.get('senha')
    cpf = data.get('cpf')
    email = data.get('email')
    email = email.lower()
    tel = data.get('telefone')
    data_nasc = data.get('data_nascimento')
    genero = data.get('genero')
    altura = data.get('altura')
    peso = data.get('peso')
    desc_obj = data.get('descricao_objetivos')

    his_med = data.get('historico_medico_relevante')
    his_med = his_med if his_med else "Nenhum"

    desc_med = data.get('descricao_medicamentos')
    desc_med = desc_med if desc_med else "Nenhum"

    desc_lim = data.get('descricao_limitacoes')
    desc_lim = desc_lim if desc_lim else "Nenhum"

    desc_tr = data.get('descricao_treinamentos_anteriores')
    desc_tr = desc_tr if desc_tr else "Nenhuma"

    if not all(
            [cpf, email, tel, data_nasc, genero, altura, peso, desc_obj]):
        return jsonify({"message": """Todos os campos são obrigatórios, 
        exceto medicamentos, limitações, histórico médico e experiência anteriores"""}), 400
    cpf1 = str(cpf)
    tel1 = str(tel)

    # Verificações de comprimento de dados
    if len(nome) > 895:
        return jsonify({"message": "Nome grande demais, o limite é 895 caracteres"}), 401
    if len(cpf1) != 11:
        return jsonify({"message": "O CPF precisa ter 11 dígitos"}), 401
    if len(tel1) != 13:
        return jsonify({"message": """O telefone precisa ser enviado
         em 13 dígitos exemplo: +55 (18) 12345-1234 = 5518123451234"""}), 401
    if len(genero) > 100:
        return jsonify({"message": "Limite de dígitos de gênero excedido (100)"}), 401
    if altura > 2.51 or altura < 0:
        return jsonify({"message": "Altura inválida"}), 401
    if '@' not in email:
        return jsonify({"message": "E-mail inválido"}), 401
    if peso < 0 or peso > 419:
        return jsonify({"message": "Peso inválido"}), 401
    if len(his_med) > 1000:
        return jsonify({"message": "Limite de caracteres de histórico médico excedido (1000)"}), 401
    if len(desc_med) > 1000:
        return jsonify({"message": "Limite de caracteres de descrição de medicamentos excedido (1000)"}), 401
    if len(desc_lim) > 1000:
        return jsonify({"message": "Limite de caracteres de descrição de limitações excedido (1000)"}), 401

    # Verificações de senha
    if len(senha1) < 8:
        return jsonify({"message": """Sua senha deve conter pelo menos oito caracteres, 
        uma letra maiúscula e minúscula e um símbolo de seu teclado."""}), 401

    tem_maiuscula = False
    tem_minuscula = False
    tem_numero = False
    tem_caract_especial = False
    caracteres_especiais = "!@#$%^&*(),-.?\":{}|<>"

    for char in senha1:
        if char.isupper():
            tem_maiuscula = True
        elif char.islower():
            tem_minuscula = True
        elif char.isdigit():
            tem_numero = True
        elif char in caracteres_especiais:
            tem_caract_especial = True

    if not tem_maiuscula:
        return jsonify({"message": """Sua senha deve conter pelo menos oito caracteres, 
        uma letra maiúscula e minúscula e um símbolo de seu teclado."""}), 401
    if not tem_minuscula:
        return jsonify({"message": """Sua senha deve conter pelo menos oito caracteres, 
        uma letra maiúscula e minúscula e um símbolo de seu teclado."""}), 401
    if not tem_numero:
        return jsonify({"message": """Sua senha deve conter pelo menos oito caracteres, 
        uma letra maiúscula e minúscula e um símbolo de seu teclado."""}), 401
    if not tem_caract_especial:
        return jsonify({"message": """Sua senha deve conter pelo menos oito caracteres, 
        uma letra maiúscula e minúscula e um símbolo de seu teclado."""}), 401

    cur = con.cursor()
    try:
        cur.execute("SELECT CPF FROM USUARIOS WHERE CPF = ?", (cpf,))
        resposta = cur.fetchone()
        if resposta:
            if resposta[0] == cpf:
                return jsonify({"message": "CPF já cadastrado"}), 401

        cur.execute("SELECT EMAIL FROM USUARIOS WHERE EMAIL = ?", (email,))
        resposta = cur.fetchone()
        if resposta:
            if resposta[0] == email:
                return jsonify({"message": "Email já cadastrado"}), 401

        cur.execute("SELECT TELEFONE FROM USUARIOS WHERE EMAIL = ?", (tel,))
        resposta = cur.fetchone()
        if resposta:
            if resposta[0] == tel:
                return jsonify({"message": "Telefone já cadastrado"}), 401

        senha2 = generate_password_hash(senha1).decode('utf-8')

        cur.execute("""INSERT INTO USUARIOS (NOME, senha, CPF, EMAIL, TELEFONE, DATA_NASCIMENTO, GENERO, ALTURA, 
        PESO, HISTORICO_MEDICO_RELEVANTE, DESCRICAO_MEDICAMENTOS, DESCRICAO_LIMITACOES, TIPO, DESCRICAO_OBJETIVOS,
        DESCRICAO_TREINAMENTOS_ANTERIORES) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,1,?,?)""",
                    (nome, senha2, cpf, email, tel, data_nasc,
                     genero, altura, peso, his_med, desc_med,
                     desc_lim, desc_obj, desc_tr))
        con.commit()
        return jsonify({"message": "Usuário cadastrado com sucesso!"}), 200

    except Exception as e:
        print("Erro em /usuarios/cadastrar")
        return jsonify({"message": "Erro em /usuarios/cadastrar", "erro": f"{e}"}), 500
    finally:
        try:
            cur.close()
        except Exception:
            pass

global_contagem_erros = {}

@app.route('/login', methods=["POST"])
def logar():
    data = request.get_json()
    email = data.get("email")
    email = email.lower()
    senha = data.get("senha")

    cur = con.cursor()
    try:
        cur.execute("SELECT senha, id_usuario FROM usuarios WHERE email = ?", (email,))
        resultado = cur.fetchone()

        if resultado:
            senha_hash = resultado[0]
            id_user = resultado[1]
            ativo = cur.execute("SELECT ATIVO FROM USUARIOS WHERE ID_USUARIO = ?", (id_user,))
            ativo = ativo.fetchone()[0]
            if not ativo:
                return jsonify(
                    {
                        "message": "Este usuário está inativado.",
                        "id_user": id_user
                    }
                ), 401

            if check_password_hash(senha_hash, senha):
                tipo = cur.execute("SELECT TIPO FROM USUARIOS WHERE ID_USUARIO = ?", (id_user,))
                tipo = tipo.fetchone()[0]

                access_token = generate_token(id_user)

                # Extrair jti para agendar exclusão
                try:
                    decoded = decode_token(access_token)
                    jti = decoded.get("jti")
                    if jti:
                        agendar_exclusao_token(jti, 3)
                except Exception:
                    # se falhar, não impede o login
                    jti = None

                id_user_str = f"usuario-{id_user}"
                if id_user_str in global_contagem_erros:
                    del global_contagem_erros[id_user_str]

                return jsonify({"message": "Login realizado com sucesso!", "token": f"{access_token}"})
            else:
                tipo = cur.execute("SELECT TIPO FROM USUARIOS WHERE ID_USUARIO = ?", (id_user,))
                tipo = tipo.fetchone()[0]

                if tipo != 3 and tipo != 2:
                    id_user_str = f"usuario-{id_user}"
                    if id_user_str not in global_contagem_erros:
                        global_contagem_erros[id_user_str] = 1
                    else:
                        global_contagem_erros[id_user_str] += 1

                        if global_contagem_erros[id_user_str] == 3:
                            cur.execute("UPDATE USUARIOS SET ATIVO = FALSE WHERE ID_USUARIO = ?", (id_user,))
                            con.commit()

                            return jsonify({"message": "Tentativas excedidas, usuário inativado."}), 401
                        elif global_contagem_erros[id_user_str] > 3:
                            global_contagem_erros[id_user_str] = 1

                    return jsonify({"message": "Credenciais inválidas."}), 401
        else:
            return jsonify({"message": "Usuário não encontrado."}), 404
    except Exception:
        print("Erro em logar")
        raise
    finally:
        try:
            cur.close()
        except Exception:
            pass


@app.route('/logout', methods=["GET"])
def logout():
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
