from main import app, con
from flask_bcrypt import generate_password_hash, check_password_hash
import jwt
import config
from apscheduler.schedulers.background import BackgroundScheduler
import datetime
from flask import jsonify, request
from email.utils import parsedate_to_datetime

# Funções globais
# Funções de token
senha_secreta = app.config['SECRET_KEY']


def agendar_exclusao_token(token, horas):
    scheduler = BackgroundScheduler()
    horario_excluir = datetime.datetime.now() + datetime.timedelta(hours=horas)
    scheduler.add_job(func=excluir_token_expirado, args=(token,), trigger='date', next_run_time=horario_excluir)
    scheduler.start()


def excluir_token_expirado(token):
    cur = con.cursor()
    try:
        cur.execute("DELETE FROM BLACKLIST_TOKENS WHERE TOKEN = ?", (token,))
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
        cur.execute("SELECT 1 FROM BLACKLIST_TOKENS WHERE TOKEN = ?", (token,))
        if cur.fetchone():
            return 6  # Acesso negado
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
                return 4  # Nível Personal trainer requerido

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
        try:
            cur.close()
        except Exception:
            pass


def informar_verificacao(tipo=0, trazer_pl=False):
    verificacao = verificar_user(tipo, trazer_pl)
    if verificacao == 1:
        return jsonify({'message': 'Token de autenticação necessário.', "verificacao": verificacao, "error": True}), 401
    elif verificacao == 2:
        return jsonify({'message': 'Token expirado.', "verificacao": verificacao, "error": True}), 401
    elif verificacao == 3:
        return jsonify({'message': 'Token inválido.', "verificacao": verificacao, "error": True}), 401
    elif verificacao == 4:
        return jsonify({'message': 'Nível Personal Trainer requerido.', "verificacao": verificacao, "error": True}), 401
    elif verificacao == 5:
        return jsonify({'message': 'Nível Administrador requerido.', "verificacao": verificacao, "error": True}), 401
    elif verificacao == 6:
        return jsonify({'message': 'Acesso negado.', "verificacao": verificacao, "error": True}), 401
    else:
        if trazer_pl:
            return verificacao
        return None


def formatar_telefone(tel):
    # 5518123451234
    # +55 (18) 12345-1234
    tel = str(tel)
    tel = ''.join(filter(str.isdigit, tel))  # Remove caracteres não numéricos
    if len(tel) == 11:
        ddd = tel[:2]
        primeira_parte = tel[2:7]
        segunda_parte = tel[7:]
        return f"({ddd}) {primeira_parte}-{segunda_parte}"
    elif len(tel) == 13:
        pais = tel[:2]
        ddd = tel[2:4]
        primeira_parte = tel[4:9]
        segunda_parte = tel[9:]
        return f"+{pais} ({ddd}) {primeira_parte}-{segunda_parte}"


def formatar_data(date_str):
    # Converte uma data no formato %Y-%m-%d para %d-%m-%Y
    return date_str.strftime("%d-%m-%Y")


@app.route('/verificartoken/<int:tipo>', methods=["GET"])
def verificar_token(tipo):
    verificacao = informar_verificacao(tipo)
    if verificacao:
        return verificacao
    else:
        return jsonify({"error": False})


# Se o tipo for 0, não há verificacão e se cadastra um cliente, se for 2, cadastra um personal trainer por admin
# Se for 3, cadastra um admin por outro admin
@app.route('/usuarios/cadastrar/<int:tipo>', methods=["POST"])
def cadastrar_usuario(tipo=0):
    if tipo >= 2:
        verificacao = informar_verificacao(tipo)
        if verificacao:
            return verificacao

    # Campos que todos os tipos de usuários precisam ter
    data = request.get_json()
    nome = data.get('nome')
    senha1 = data.get('senha')
    cpf = data.get('cpf')
    email = data.get('email')
    email = email.lower()
    tel = data.get('telefone')
    data_nasc = data.get('data_nascimento')
    data_nasc = data_nasc.replace("/", "-")

    if tipo == 0:
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
                [nome, senha1, cpf, email, tel, data_nasc, desc_obj]):
            return jsonify({"message": """Todos os campos são obrigatórios, 
            exceto medicamentos, limitações, histórico médico e experiência anteriores""", "error": True}), 400
        if len(his_med) > 1000:
            return jsonify({"message": "Limite de caracteres de histórico médico excedido (1000)", "error": True}), 401
        if len(desc_med) > 1000:
            return jsonify(
                {"message": "Limite de caracteres de descrição de medicamentos excedido (1000)", "error": True}), 401
        if len(desc_lim) > 1000:
            return jsonify(
                {"message": "Limite de caracteres de descrição de limitações excedido (1000)", "error": True}), 401
        if len(desc_tr) > 1000:
            return jsonify({"message": "Limite de caracteres de descrição de treinamentos anteriores excedido (1000)",
                            "error": True}), 401
        if len(desc_obj) > 1000:
            return jsonify(
                {"message": "Limite de caracteres de descrição de objetivos excedido (1000)", "error": True}), 401

    elif tipo == 2:
        form = data.get('formacao')
        cref = data.get('cref')

        if not all(
                [nome, data_nasc, senha1, cpf, email, tel, form, cref]):
            return jsonify({"message": """Todos os campos são obrigatórios""", "error": True}), 400

        if cref:
            if len(str(cref)) > 6:
                return jsonify({"message": "Limite de caracteres de registro CREF excedido (6)", "error": True}), 401
        if form:
            if len(form) > 1000:
                return jsonify({"message": "Limite de caracteres de formação excedido (1000)", "error": True}), 401
    else:
        if tipo != 3:
            return jsonify({"message": "Tipo não identificado na URL, precisa ser 0, 2 ou 3", "error": True}), 400
        else:
            if not all(
                    [nome, data_nasc, senha1, cpf, email, tel]):
                return jsonify({"message": """Todos os campos são obrigatórios""", "error": True}), 400

    # Verificações de comprimento e formatação de dados
    try:
        ano_nasc = datetime.datetime.strptime(data_nasc, "%d-%m-%Y")  # converte para datetime
        data_nasc = ano_nasc
        ano_nasc = ano_nasc.year
        hoje_ano = datetime.date.today().year

        if ano_nasc > hoje_ano or hoje_ano - ano_nasc < 17:
            return jsonify({"message": "Data de nasicmento inválida", "error": True}), 401
    except Exception:
        return jsonify({"message":
                            f"""Erro ao transformar data, formato esperado: %d-%m-%Y, formato recebido: {data_nasc}"""}), 400

    cpf1 = str(cpf)
    tel1 = str(tel)

    if len(nome) > 895:
        return jsonify({"message": "Nome grande demais, o limite é 895 caracteres", "error": True}), 401
    if len(cpf1) != 11:
        return jsonify({"message": "O CPF precisa ter 11 dígitos", "error": True}), 401
    if len(tel1) != 13:
        return jsonify({"message": """O telefone precisa ser enviado
                 em 13 dígitos exemplo: +55 (18) 12345-1234 = 5518123451234""", "error": True}), 401
    if '@' not in email:
        return jsonify({"message": "E-mail inválido", "error": True}), 401

    # Verificações de senha

    if len(senha1) < 8:
        return jsonify({"message": """Sua senha deve conter pelo menos oito caracteres, 
        uma letra maiúscula e minúscula e um símbolo de seu teclado.""", "error": True}), 401

    tem_maiuscula = False
    tem_minuscula = False
    tem_numero = False
    tem_caract_especial = False
    caracteres_especiais = "!@#$%^&*(),-.?\":{}|<>"

    # Verifica cada caractere da senha
    for char in senha1:
        if char.isupper():
            tem_maiuscula = True
        elif char.islower():
            tem_minuscula = True
        elif char.isdigit():
            tem_numero = True
        elif char in caracteres_especiais:
            tem_caract_especial = True

    # Verifica se todos os critérios foram atendidos
    if not tem_maiuscula:
        return jsonify({"message": """Sua senha deve conter pelo menos oito caracteres, 
        uma letra maiúscula e minúscula e um símbolo de seu teclado.""", "error": True}), 401
    if not tem_minuscula:
        return jsonify({"message": """Sua senha deve conter pelo menos oito caracteres, 
        uma letra maiúscula e minúscula e um símbolo de seu teclado.""", "error": True}), 401
    if not tem_numero:
        return jsonify({"message": """Sua senha deve conter pelo menos oito caracteres, 
        uma letra maiúscula e minúscula e um símbolo de seu teclado.""", "error": True}), 401
    if not tem_caract_especial:
        return jsonify({"message": """Sua senha deve conter pelo menos oito caracteres, 
        uma letra maiúscula e minúscula e um símbolo de seu teclado.""", "error": True}), 401

    cur = con.cursor()
    try:
        cur.execute("SELECT CPF FROM USUARIOS WHERE CPF = ?", (cpf1,))
        # Verificações a partir do banco de dados
        # Verificações de duplicatas
        resposta = cur.fetchone()
        if resposta:
            if resposta[0] == cpf1:
                return jsonify({"message": "CPF já cadastrado", "error": True}), 401

        cur.execute("SELECT EMAIL FROM USUARIOS WHERE EMAIL = ?", (email,))
        resposta = cur.fetchone()
        if resposta:
            if resposta[0] == email:
                return jsonify({"message": "Email já cadastrado", "error": True}), 401

        cur.execute("SELECT TELEFONE FROM USUARIOS WHERE TELEFONE = ?", (tel1,))
        resposta = cur.fetchone()
        if resposta:
            if resposta[0] == tel1:
                return jsonify({"message": "Telefone já cadastrado", "error": True}), 401

        senha2 = generate_password_hash(senha1).decode('utf-8')

        if tipo == 0:

            cur.execute("""INSERT INTO USUARIOS (NOME, senha, CPF, EMAIL, TELEFONE, DATA_NASCIMENTO, 
                        HISTORICO_MEDICO_RELEVANTE, DESCRICAO_MEDICAMENTOS, DESCRICAO_LIMITACOES, TIPO, 
                        DESCRICAO_OBJETIVOS,
                        DESCRICAO_TREINAMENTOS_ANTERIORES) VALUES (?,?,?,?,?,?,?,?,?,1,?,?)""",
                        (nome, senha2, cpf1, email, formatar_telefone(tel1), data_nasc,
                         his_med, desc_med,
                         desc_lim, desc_obj, desc_tr))
        elif tipo == 2:
            cur.execute("""INSERT INTO USUARIOS (NOME, senha, CPF, EMAIL, TELEFONE, DATA_NASCIMENTO, 
                        FORMACAO, REGISTRO_CREF, TIPO) VALUES (?,?,?,?,?,?,?,?,2)""",
                        (nome, senha2, cpf1, email, formatar_telefone(tel1), data_nasc,
                         form, cref))

        else:
            cur.execute("""INSERT INTO USUARIOS (NOME, senha, CPF, EMAIL, TELEFONE, DATA_NASCIMENTO, 
                        TIPO) VALUES (?,?,?,?,?,?,3)""",
                        (nome, senha2, cpf1, email, formatar_telefone(tel1), data_nasc,))
        con.commit()
        return jsonify({"message": "Usuário cadastrado com sucesso!", "error": False}), 200

    except Exception:
        print("Erro em /usuarios/cadastrar/<int:tipo>")
        raise
    finally:
        try:
            cur.close()
        except Exception:
            pass


# Para editar a si mesmo
@app.route("/usuarios/editar", methods=["PUT"])
def editar_perfil():
    verificacao = informar_verificacao()
    if verificacao:
        return verificacao
    id_usuario = informar_verificacao(trazer_pl=True)
    id_usuario = id_usuario['id_usuario']

    data = request.get_json()
    nome = data.get("nome")
    senha1 = data.get("senha")
    cpf = data.get("cpf")
    email = data.get("email")
    email = email.lower()
    tel = data.get("telefone")
    data_nasc = data.get("data_nascimento")
    data_nasc = data_nasc.replace("/", "-")
    his_med = data.get("historico_medico_relevante")
    desc_med = data.get("descricao_medicamentos")
    desc_lim = data.get("descricao_limitacoes")
    desc_obj = data.get("descricao_objetivos")
    desc_tr = data.get("descricao_treinamentos_anteriores")
    form = data.get("formacao")
    cref = data.get("cref")

    # Verificações de comprimento e formatação de dados
    if data_nasc:
        try:
            ano_nasc = datetime.datetime.strptime(data_nasc, "%d-%m-%Y")  # converte para datetime
            data_nasc = ano_nasc
            ano_nasc = ano_nasc.year
            hoje_ano = datetime.date.today().year

            if ano_nasc > hoje_ano or hoje_ano - ano_nasc < 17:
                return jsonify({"message": "Data de nasicmento inválida", "error": True}), 401
        except Exception:
            return jsonify({"message":
                            f"""Erro ao transformar data, formato esperado: %d-%m-%Y, formato recebido: {data_nasc}"""}), 400
    cpf1 = str(cpf)
    tel1 = str(tel)

    if nome:
        if len(nome) > 895:
            return jsonify({"message": "Nome grande demais, o limite é 895 caracteres", "error": True}), 401
    if cpf:
        if len(cpf1) != 11:
            return jsonify({"message": "O CPF precisa ter 11 dígitos", "error": True}), 401
    if tel:
        if len(tel1) != 13:
            return jsonify({"message": """O telefone precisa ser enviado
                 em 13 dígitos exemplo: +55 (18) 12345-1234 = 5518123451234""", "error": True}), 401
    if '@' not in email:
        return jsonify({"message": "E-mail inválido", "error": True}), 401
    if his_med:
        if len(his_med) > 1000:
            return jsonify({"message": "Limite de caracteres de histórico médico excedido (1000)", "error": True}), 401
    if desc_med:
        if len(desc_med) > 1000:
            return jsonify(
                {"message": "Limite de caracteres de descrição de medicamentos excedido (1000)", "error": True}), 401
    if desc_lim:
        if len(desc_lim) > 1000:
            return jsonify(
                {"message": "Limite de caracteres de descrição de limitações excedido (1000)", "error": True}), 401
    if desc_tr:
        if len(desc_tr) > 1000:
            return jsonify({"message": "Limite de caracteres de descrição de treinamentos anteriores excedido (1000)",
                            "error": True}), 401
    if desc_obj:
        if len(desc_obj) > 1000:
            return jsonify(
                {"message": "Limite de caracteres de descrição de objetivos excedido (1000)", "error": True}), 401
    if cref:
        if len(str(cref)) > 6:
            return jsonify({"message": "Limite de caracteres de registro CREF excedido (6)", "error": True}), 401
    if form:
        if len(form) > 1000:
            return jsonify({"message": "Limite de caracteres de formação excedido (1000)", "error": True}), 401

    # Verificações de senha

    if len(senha1) < 8:
        return jsonify({"message": """Sua senha deve conter pelo menos oito caracteres,
            uma letra maiúscula e minúscula e um símbolo de seu teclado.""", "error": True}), 401

    tem_maiuscula = False
    tem_minuscula = False
    tem_numero = False
    tem_caract_especial = False
    caracteres_especiais = "!@#$%^&*(),-.?\":{}|<>"

    # Verifica cada caractere da senha
    for char in senha1:
        if char.isupper():
            tem_maiuscula = True
        elif char.islower():
            tem_minuscula = True
        elif char.isdigit():
            tem_numero = True
        elif char in caracteres_especiais:
            tem_caract_especial = True

    # Verifica se todos os critérios foram atendidos
    if not tem_maiuscula:
        return jsonify({"message": """Sua senha deve conter pelo menos oito caracteres,
            uma letra maiúscula e minúscula e um símbolo de seu teclado.""", "error": True}), 401
    if not tem_minuscula:
        return jsonify({"message": """Sua senha deve conter pelo menos oito caracteres,
            uma letra maiúscula e minúscula e um símbolo de seu teclado.""", "error": True}), 401
    if not tem_numero:
        return jsonify({"message": """Sua senha deve conter pelo menos oito caracteres,
            uma letra maiúscula e minúscula e um símbolo de seu teclado.""", "error": True}), 401
    if not tem_caract_especial:
        return jsonify({"message": """Sua senha deve conter pelo menos oito caracteres,
            uma letra maiúscula e minúscula e um símbolo de seu teclado.""", "error": True}), 401

    cur = con.cursor()
    try:
        # Verificações de duplicatas
        cur.execute("SELECT CPF FROM USUARIOS WHERE CPF = ? AND ID_USUARIO <> ?", (cpf1, id_usuario,))
        resposta = cur.fetchone()
        if resposta:
            if resposta[0] == cpf1:
                return jsonify({"message": "CPF já cadastrado", "error": True}), 401

        cur.execute("SELECT EMAIL FROM USUARIOS WHERE EMAIL = ? AND ID_USUARIO <> ?", (email, id_usuario,))
        resposta = cur.fetchone()
        if resposta:
            if resposta[0] == email:
                return jsonify({"message": "Email já cadastrado", "error": True}), 401

        cur.execute("SELECT TELEFONE FROM USUARIOS WHERE TELEFONE = ? AND ID_USUARIO <> ?", (tel1, id_usuario,))
        resposta = cur.fetchone()
        if resposta:
            if resposta[0] == tel1:
                return jsonify({"message": "Telefone já cadastrado", "error": True}), 401

        cur.execute("SELECT REGISTRO_CREF FROM USUARIOS WHERE REGISTRO_CREF = ? AND ID_USUARIO <> ?",
                    (cref, id_usuario,))
        resposta = cur.fetchone()
        if resposta:
            if resposta[0] == str(cref):
                return jsonify({"message": "Registro de CREF já cadastrado", "error": True}), 401

        # Pegando valores padrões
        cur.execute("""SELECT NOME, SENHA, CPF, EMAIL, TELEFONE, DATA_NASCIMENTO, HISTORICO_MEDICO_RELEVANTE, 
        DESCRICAO_MEDICAMENTOS, DESCRICAO_LIMITACOES, DESCRICAO_OBJETIVOS, DESCRICAO_TREINAMENTOS_ANTERIORES, 
        FORMACAO, REGISTRO_CREF FROM USUARIOS WHERE ID_USUARIO = ?""", (id_usuario,))
        resposta = cur.fetchone()
        if resposta:
            # Trocando os valores não recebidos pelos existentes no banco
            nome = resposta[0] if not nome else nome
            senha_hash = resposta[1]
            cpf1 = str(resposta[2]) if not cpf else cpf1
            email = resposta[3] if not email else email
            tel = resposta[4] if not tel else tel
            data_nasc = resposta[5] if not data_nasc else data_nasc
            his_med = resposta[6] if not his_med else his_med
            desc_med = resposta[7] if not desc_med else desc_med
            desc_lim = resposta[8] if not desc_lim else desc_lim
            desc_obj = resposta[9] if not desc_obj else desc_obj
            desc_tr = resposta[10] if not desc_tr else desc_tr
            form = resposta[11] if not form else form
            cref = resposta[12] if not cref else cref

        if senha1:
            senha_hash = generate_password_hash(senha1).decode('utf-8')

        cur.execute("""UPDATE USUARIOS SET NOME = ?, SENHA = ?, CPF = ?, EMAIL = ?, TELEFONE = ?, 
        DATA_NASCIMENTO = ?, HISTORICO_MEDICO_RELEVANTE = ?, DESCRICAO_MEDICAMENTOS = ?,
        DESCRICAO_LIMITACOES = ?, DESCRICAO_OBJETIVOS = ?, DESCRICAO_TREINAMENTOS_ANTERIORES = ?, FORMACAO = ?, 
        REGISTRO_CREF = ? WHERE ID_USUARIO = ?""", (nome, senha_hash, cpf1, email, formatar_telefone(tel), data_nasc,
                                                    his_med, desc_med,
                                                    desc_lim, desc_obj, desc_tr, form, str(cref), id_usuario,))

        con.commit()

        return jsonify({"message": "Usuário editado com sucesso!", "error": "False"}), 200

    except Exception:
        print("Erro em /usuarios/editar")
        raise
    finally:
        try:
            cur.close()
        except Exception:
            pass


# Entrega os campos de dados já existentes para o usuário se editar
@app.route('/usuarios/info', methods=["GET"])
def trazer_campos_editar_a_si_mesmo():
    verificacao = informar_verificacao()
    if verificacao:
        return verificacao

    id_logado = informar_verificacao(trazer_pl=True)
    id_logado = id_logado["id_usuario"]

    cur = con.cursor()
    try:
        cur.execute("SELECT TIPO FROM USUARIOS WHERE ID_USUARIO = ?", (id_logado, ))
        dicionario = {}
        subtitulos = []

        tipo = cur.fetchone()
        if tipo:
            if tipo[0] == 1:
                cur.execute(f"""SELECT NOME, EMAIL, TELEFONE, CPF, DATA_NASCIMENTO, HISTORICO_MEDICO_RELEVANTE, 
                                DESCRICAO_MEDICAMENTOS, DESCRICAO_LIMITACOES, DESCRICAO_OBJETIVOS, 
                                DESCRICAO_TREINAMENTOS_ANTERIORES FROM USUARIOS WHERE ID_USUARIO = ?""", (id_logado,))
                subtitulos = ["nome", "email", "telefone", "cpf", "data_nascimento",
                              "historico_medico_relevante", "descricao_medicamentos", "descricao_limitações",
                              "descricao_objetivos", "descricao_treinamentos_anteriores"]
            elif tipo[0] == 2:
                cur.execute(f"""SELECT NOME, EMAIL, TELEFONE, CPF, DATA_NASCIMENTO, REGISTRO_CREF, FORMACAO
                                FROM USUARIOS WHERE ID_USUARIO = ?""", (id_logado,))
                subtitulos = ["nome", "email", "telefone", "cpf", "data_nascimento", "cref", "formacao"]
            elif tipo[0] == 3:
                cur.execute(f"""SELECT NOME, EMAIL, TELEFONE, CPF, DATA_NASCIMENTO
                                FROM USUARIOS WHERE ID_USUARIO = ?""", (id_logado,))
                subtitulos = ["nome", "email", "telefone", "cpf", "data_nascimento"]
            dados = cur.fetchone()
            x = 0
            for dado in dados:
                try:
                    if subtitulos[x] == "data_nascimento":
                        data_nasc = formatar_data(dado)
                        dicionario[subtitulos[x]] = str(data_nasc)
                    else:
                        dicionario[subtitulos[x]] = dado
                except IndexError:
                    return jsonify({"message": "Erro ao recuperar campos de dado do usuário", "error": True}), 500
                x += 1
            # dados_json = dict(zip(subtitulos, dados))

            return jsonify({"dados": dicionario, "error": False}), 200

    except Exception:
        print("Erro em /usuarios/info")
        raise
    finally:
        try:
            cur.close()
        except Exception:
            pass


@app.route("/usuarios/<int:tipo_logado>/<int:pagina>/<int:tipo_listar>", methods=["GET"])
def listar_usuarios(tipo_logado, pagina=1, tipo_listar=1):  # Se a página for 0, retornar o total de páginas disponíveis
    # Lista todos os usuários e suas informações conforme as permissões de quem está logado
    if tipo_logado > 2:
        verificacao = informar_verificacao(3)
        if verificacao:
            return verificacao
    else:
        verificacao = informar_verificacao(2)
        if verificacao:
            return verificacao

    tipo_listar = 3 if tipo_listar > 3 else tipo_listar
    tipo_listar = 1 if tipo_listar < 1 else tipo_listar
    cur = con.cursor()
    try:
        if pagina == 0:
            cur.execute("SELECT COUNT(ID_USUARIO) FROM USUARIOS WHERE TIPO = ?", (tipo_listar, ))
            qtd_paginas = cur.fetchone()
            qtd_paginas = qtd_paginas[0]
            # print(qtd_paginas, qtd_paginas/8, qtd_paginas % 8 != 0, qtd_paginas // 8 + 1)
            if qtd_paginas % 8 != 0:  # Se tem resto adiciona um
                qtd_paginas = (qtd_paginas // 8) + 1
            else:
                qtd_paginas = qtd_paginas / 8

            return jsonify({"paginas": int(qtd_paginas)})
        inicial = pagina * 8 - 7 if pagina == 1 else pagina * 8 - 7
        final = pagina * 8
        if tipo_listar == 1:
            cur.execute(f"""SELECT ID_USUARIO, NOME, EMAIL, CPF, TELEFONE, ATIVO FROM USUARIOS 
            WHERE TIPO = 1 ORDER BY ID_USUARIO DESC ROWS {inicial} TO {final}""")
        elif tipo_listar == 2:
            cur.execute(f"""SELECT ID_USUARIO, NOME, EMAIL, REGISTRO_CREF, TELEFONE, ATIVO FROM USUARIOS 
            WHERE TIPO = 2 ORDER BY ID_USUARIO DESC ROWS {inicial} TO {final}""")
        elif tipo_listar == 3:
            if tipo_logado < 3:
                return jsonify({"message": "Você não tem permissão para ver esse tipo de usuário", "error": True}), 401
            cur.execute(f"""SELECT ID_USUARIO, NOME, EMAIL, TELEFONE, ATIVO FROM USUARIOS 
                        WHERE TIPO = 3 ORDER BY ID_USUARIO DESC ROWS {inicial} TO {final}""")
        else:
            return jsonify({"message": "Tipo inválido, precisa ser 1, 2 ou 3", "error": True}), 400
        usuarios = cur.fetchall()
        # [inicial - 1:final]
        return jsonify({"usuarios": usuarios, "error": False}), 200
    except Exception:
        print("Erro em /usuarios/admin/<int:pagina>/<int:tipo>")
        raise
    finally:
        try:
            cur.close()
        except Exception:
            pass


@app.route("/usuarios/info/<int:id_usuario>/<int:tipo_logado>", methods=["GET"])
def trazer_campos_editar_outro(id_usuario, tipo_logado):
    if tipo_logado > 2:
        verificacao = informar_verificacao(3)
        if verificacao:
            return verificacao
    else:
        verificacao = informar_verificacao(2)
        if verificacao:
            return verificacao

    cur = con.cursor()
    try:
        cur.execute("SELECT TIPO FROM USUARIOS WHERE ID_USUARIO = ?", (id_usuario,))
        resposta = cur.fetchone()
        subtitulos = []
        dicionario = {}
        if resposta:
            tipo = resposta[0]
            if tipo == 1:
                cur.execute("""SELECT NOME, ATIVO, CPF, EMAIL, TELEFONE, DATA_NASCIMENTO, 
                 HISTORICO_MEDICO_RELEVANTE, DESCRICAO_MEDICAMENTOS, DESCRICAO_LIMITACOES, DESCRICAO_OBJETIVOS, 
                 DESCRICAO_TREINAMENTOS_ANTERIORES  
                 FROM USUARIOS WHERE ID_USUARIO = ?""", (id_usuario,))
                subtitulos = ["nome", "ativo", "cpf", "email", "telefone", "data_nascimento",
                              "historico_medico_relevante", "descricao_medicamentos", "descricao_limitações",
                              "descricao_objetivos", "descricao_treinamentos_anteriores"]
            elif tipo == 2:
                cur.execute("""SELECT NOME, ATIVO, CPF, EMAIL, TELEFONE, DATA_NASCIMENTO,
                 FORMACAO, REGISTRO_CREF 
                 FROM USUARIOS WHERE ID_USUARIO = ?""", (id_usuario,))
                subtitulos = ["nome", "ativo", "cpf", "email", "telefone", "data_nascimento", "formacao",
                              "cref"]
                if tipo_logado < 3:
                    return jsonify({"message": "Você não tem permissão de ver os dados desse usuário",
                                    "error": True}), 401
                cur.execute("""SELECT NOME, ATIVO, CPF, EMAIL, TELEFONE, DATA_NASCIMENTO 
                 FROM USUARIOS WHERE ID_USUARIO = ?""", (id_usuario,))
                subtitulos = ["nome", "ativo", "cpf", "email", "telefone", "data_nascimento"]
            else:
                return jsonify({"message": "Erro ao recuperar tipo de usuário", "error": True}), 500
        else:
            return jsonify({"message": "Usuário não encontrado", "error": True}), 404

        dados = cur.fetchone()
        x = 0
        for dado in dados:
            try:
                if subtitulos[x] == "data_nascimento":
                    data_nasc = formatar_data(dado)
                    dicionario[subtitulos[x]] = str(data_nasc)
                else:
                    dicionario[subtitulos[x]] = dado
            except IndexError:
                return jsonify({"message": "Erro ao recuperar campos de dado do usuário", "error": True}), 500
            x += 1
        # dados_json = dict(zip(subtitulos, dados))

        return jsonify({"dados": dicionario, "error": False}), 200
    except Exception:
        print("Erro em /usuarios/info/<int:id_usuario>/<int:tipo_logado>")
        raise
    finally:
        try:
            cur.close()
        except Exception:
            pass


@app.route("/usuarios/<int:id_usuario>/editar/<int:tipo_logado>", methods=["PUT"])
def editar_outro_usuario(id_usuario, tipo_logado):
    if tipo_logado > 2:
        verificacao = informar_verificacao(3)
        if verificacao:
            return verificacao
    else:
        verificacao = informar_verificacao(2)
        if verificacao:
            return verificacao

    data = request.get_json()
    nome = data.get("nome")
    senha1 = data.get("senha")
    cpf = data.get("cpf")
    email = data.get("email")
    if email:
        email = email.lower()
    tel = data.get("telefone")
    data_nasc = data.get("data_nascimento")
    if data_nasc:
        data_nasc = data_nasc.replace("/", "-")
    # ---
    his_med = data.get("historico_medico_relevante")
    desc_med = data.get("descricao_medicamentos")
    desc_lim = data.get("descricao_limitacoes")
    desc_obj = data.get("descricao_objetivos")
    desc_tr = data.get("descricao_treinamentos_anteriores")
    # ---
    form = data.get("formacao")
    cref = data.get("cref")

    # Verificações de comprimento e formatação de dados
    if data_nasc:
        try:
            ano_nasc = datetime.datetime.strptime(data_nasc, "%d-%m-%Y")  # converte para datetime
            data_nasc = ano_nasc
            ano_nasc = ano_nasc.year
            hoje_ano = datetime.date.today().year

            if ano_nasc > hoje_ano or hoje_ano - ano_nasc < 17:
                return jsonify({"message": "Data de nasicmento inválida", "error": True}), 401
        except Exception:
            return jsonify({"message":
                                f"""Erro ao transformar data, formato esperado: %d-%m-%Y, formato recebido: {data_nasc}"""}), 400
    cpf1 = str(cpf) if cpf else None
    tel1 = str(tel) if tel else None
    cref = str(cref) if cref else None

    if nome:
        if len(nome) > 895:
            return jsonify({"message": "Nome grande demais, o limite é 895 caracteres", "error": True}), 401
    if cpf:
        if len(cpf1) != 11:
            return jsonify({"message": "O CPF precisa ter 11 dígitos", "error": True}), 401
    if tel:
        if len(tel1) != 13:
            return jsonify({"message": """O telefone precisa ser enviado
                     em 13 dígitos exemplo: +55 (18) 12345-1234 = 5518123451234""", "error": True}), 401
    if email:
        if '@' not in email:
            return jsonify({"message": "E-mail inválido", "error": True}), 401
    if his_med:
        if len(his_med) > 1000:
            return jsonify({"message": "Limite de caracteres de histórico médico excedido (1000)", "error": True}), 401
    if desc_med:
        if len(desc_med) > 1000:
            return jsonify(
                {"message": "Limite de caracteres de descrição de medicamentos excedido (1000)", "error": True}), 401
    if desc_lim:
        if len(desc_lim) > 1000:
            return jsonify(
                {"message": "Limite de caracteres de descrição de limitações excedido (1000)", "error": True}), 401
    if desc_tr:
        if len(desc_tr) > 1000:
            return jsonify({"message": "Limite de caracteres de descrição de treinamentos anteriores excedido (1000)",
                            "error": True}), 401
    if desc_obj:
        if len(desc_obj) > 1000:
            return jsonify(
                {"message": "Limite de caracteres de descrição de objetivos excedido (1000)", "error": True}), 401
    if cref:
        if len(cref) > 9:
            return jsonify({"message": "Limite de caracteres de registro CREF excedido (9)", "error": True}), 401
    if form:
        if len(form) > 1000:
            return jsonify({"message": "Limite de caracteres de formação excedido (1000)", "error": True}), 401

    # Verificações de senha, se houver senha
    if senha1:
        if len(senha1) < 8:
            return jsonify({"message": """Sua senha deve conter pelo menos oito caracteres,
                    uma letra maiúscula e minúscula e um símbolo de seu teclado.""", "error": True}), 401

        tem_maiuscula = False
        tem_minuscula = False
        tem_numero = False
        tem_caract_especial = False
        caracteres_especiais = "!@#$%^&*(),-.?\":{}|<>"

        # Verifica cada caractere da senha
        for char in senha1:
            if char.isupper():
                tem_maiuscula = True
            elif char.islower():
                tem_minuscula = True
            elif char.isdigit():
                tem_numero = True
            elif char in caracteres_especiais:
                tem_caract_especial = True

        # Verifica se todos os critérios foram atendidos
        if not tem_maiuscula:
            return jsonify({"message": """Sua senha deve conter pelo menos oito caracteres,
                    uma letra maiúscula e minúscula e um símbolo de seu teclado.""", "error": True}), 401
        if not tem_minuscula:
            return jsonify({"message": """Sua senha deve conter pelo menos oito caracteres,
                    uma letra maiúscula e minúscula e um símbolo de seu teclado.""", "error": True}), 401
        if not tem_numero:
            return jsonify({"message": """Sua senha deve conter pelo menos oito caracteres,
                    uma letra maiúscula e minúscula e um símbolo de seu teclado.""", "error": True}), 401
        if not tem_caract_especial:
            return jsonify({"message": """Sua senha deve conter pelo menos oito caracteres,
                    uma letra maiúscula e minúscula e um símbolo de seu teclado.""", "error": True}), 401

    cur = con.cursor()
    try:
        # Verificações de duplicatas
        cur.execute("SELECT CPF FROM USUARIOS WHERE CPF = ? AND ID_USUARIO <> ?", (cpf1, id_usuario,))
        resposta = cur.fetchone()
        if resposta:
            if resposta[0] == cpf1:
                return jsonify({"message": "CPF já cadastrado", "error": True}), 401

        cur.execute("SELECT EMAIL FROM USUARIOS WHERE EMAIL = ? AND ID_USUARIO <> ?", (email, id_usuario,))
        resposta = cur.fetchone()
        if resposta:
            if resposta[0] == email:
                return jsonify({"message": "Email já cadastrado", "error": True}), 401

        cur.execute("SELECT TELEFONE FROM USUARIOS WHERE TELEFONE = ? AND ID_USUARIO <> ?", (tel1, id_usuario,))
        resposta = cur.fetchone()
        if resposta:
            if resposta[0] == tel1:
                return jsonify({"message": "Telefone já cadastrado", "error": True}), 401

        if cref:
            cur.execute("SELECT REGISTRO_CREF FROM USUARIOS WHERE REGISTRO_CREF = ? AND ID_USUARIO <> ?",
                        (cref, id_usuario,))
            resposta = cur.fetchone()
            if resposta:
                if resposta[0] == cref:
                    return jsonify({"message": "Registro de CREF já cadastrado", "error": True}), 401

        # Pegando valores padrões
        cur.execute("""SELECT NOME, SENHA, CPF, EMAIL, TELEFONE, DATA_NASCIMENTO, HISTORICO_MEDICO_RELEVANTE, 
            DESCRICAO_MEDICAMENTOS, DESCRICAO_LIMITACOES, DESCRICAO_OBJETIVOS, DESCRICAO_TREINAMENTOS_ANTERIORES, 
            FORMACAO, REGISTRO_CREF, TIPO FROM USUARIOS WHERE ID_USUARIO = ?""", (id_usuario,))
        resposta = cur.fetchone()
        if resposta:
            # Trocando os valores não recebidos pelos existentes no banco
            nome = resposta[0] if not nome else nome
            senha_hash = resposta[1]
            cpf1 = str(resposta[2]) if not cpf else cpf1
            email = resposta[3] if not email else email
            tel1 = str(resposta[4]) if not tel else tel1
            data_nasc = resposta[5] if not data_nasc else data_nasc
            his_med = resposta[6] if not his_med else his_med
            desc_med = resposta[7] if not desc_med else desc_med
            desc_lim = resposta[8] if not desc_lim else desc_lim
            desc_obj = resposta[9] if not desc_obj else desc_obj
            desc_tr = resposta[10] if not desc_tr else desc_tr
            form = resposta[11] if not form else form
            cref = resposta[12] if not cref else cref

            tipo = resposta[13]  # O tipo aqui serve apenas para verificação, não para mudar na edição
            if tipo != 2:
                form = None
                cref = None
            if tipo != 1:
                his_med = None
                desc_med = None
                desc_lim = None
                desc_obj = None
                desc_tr = None

        if senha1:
            senha_hash = generate_password_hash(senha1).decode('utf-8')

        cur.execute("""UPDATE USUARIOS SET NOME = ?, SENHA = ?, CPF = ?, EMAIL = ?, TELEFONE = ?, 
            DATA_NASCIMENTO = ?, HISTORICO_MEDICO_RELEVANTE = ?, DESCRICAO_MEDICAMENTOS = ?,
            DESCRICAO_LIMITACOES = ?, DESCRICAO_OBJETIVOS = ?, DESCRICAO_TREINAMENTOS_ANTERIORES = ?, FORMACAO = ?, 
            REGISTRO_CREF = ? WHERE ID_USUARIO = ?""",
                    (nome, senha_hash, cpf1, email, formatar_telefone(tel1), data_nasc, his_med, desc_med, desc_lim,
                     desc_obj, desc_tr, form, cref, id_usuario,))

        con.commit()

        return jsonify({"message": "Usuário editado com sucesso!", "error": "False"}), 200

    except Exception:
        print("Erro em /usuarios/<int:id_usuario>/editar/<int:tipo_logado>")
        raise
    finally:
        try:
            cur.close()
        except Exception:
            pass


# TESTAR E CORRIGIR
@app.route("/usuarios/<int:id_usuario>/alternar-ativo", methods=["GET"])
def alternar_ativo_de_usuario(id_usuario):

    cur = con.cursor()
    try:
        # Verificar o id_usuario
        cur.execute("SELECT TIPO, ATIVO FROM USUARIOS WHERE ID_USUARIO = ?", (id_usuario, ))
        resultado = cur.fetchone()
        if not resultado:
            return jsonify({"message": "Usuário não encontrado", "error": True}), 404
        if resultado[0] > 1:
            verificacao = informar_verificacao(3)
            if verificacao:
                return verificacao
            if resultado[0] == 3:
                return jsonify({"message": "Esse usuário não pode ser inativado"})
        else:
            verificacao = informar_verificacao(2)
            if verificacao:
                return verificacao

        if resultado[1]:  # Se ativo == True
            cur.execute("UPDATE USUARIOS SET ATIVO = FALSE WHERE ID_USUARIO = ?", (id_usuario, ))
            return jsonify({"message": "Usuário inativado com sucesso!", "error": False})
        else:  # Se resultado != True
            cur.execute("UPDATE USUARIOS SET ATIVO = TRUE WHERE ID_USUARIO = ?", (id_usuario,))
            return jsonify({"message": "Usuário reativado com sucesso!", "error": False})
    except Exception:
        print("erro em /usuarios/<int:id_usuario>/alternar-ativo")
        raise
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
        # Checando se a senha está correta
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
                        "id_user": id_user,
                        "error": True
                    }
                ), 401

            if check_password_hash(senha_hash, senha):
                tipo = cur.execute("SELECT TIPO FROM USUARIOS WHERE ID_USUARIO = ?", (id_user,))
                tipo = tipo.fetchone()[0]

                nome = cur.execute("SELECT NOME FROM USUARIOS WHERE ID_USUARIO = ?", (id_user,))
                nome = nome.fetchone()[0]

                token = generate_token(id_user)

                # limpar global_contagem_erros e etc...

                token = remover_bearer(token)

                tipo = cur.execute("SELECT TIPO FROM USUARIOS WHERE ID_USUARIO = ?", (id_user,))
                tipo = tipo.fetchone()[0]
                # Excluir as tentativas que deram errado
                id_user_str = f"usuario-{id_user}"
                if id_user_str in global_contagem_erros:
                    del global_contagem_erros[id_user_str]

                return jsonify({"message": "Login realizado com sucesso!",
                                "token": token,
                                "nome": nome,
                                "tipo": tipo,
                                "email": email,
                                "error": False}), 200
            else:
                # Ignorar isso tudo se o usuário for administrador ou personal trainer
                tipo = cur.execute("SELECT TIPO FROM USUARIOS WHERE ID_USUARIO = ?", (id_user,))
                tipo = tipo.fetchone()[0]

                if tipo != 3:
                    id_user_str = f"usuario-{id_user}"
                    if id_user_str not in global_contagem_erros:
                        global_contagem_erros[id_user_str] = 1
                    else:
                        global_contagem_erros[id_user_str] += 1

                        if global_contagem_erros[id_user_str] == 3:
                            cur.execute("UPDATE USUARIOS SET ATIVO = FALSE WHERE ID_USUARIO = ?", (id_user,))
                            con.commit()

                            return jsonify({"message": "Tentativas excedidas, usuário inativado.", "error": True}), 401
                        elif global_contagem_erros[id_user_str] > 3:
                            global_contagem_erros[id_user_str] = 1
                            # Em teoria é para ser impossível a execução chegar aqui

                return jsonify({"message": "Credenciais inválidas.", "error": True}), 401
        else:
            return jsonify({"message": "Usuário não encontrado.", "error": True}), 404
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
    verificacao = informar_verificacao()
    if verificacao:
        return jsonify({"message": "Você já saiu de sua conta", "error": True}), 401

    token = request.headers.get('Authorization')
    token = remover_bearer(token)

    cur = con.cursor()
    try:
        cur.execute("SELECT 1 FROM BLACKLIST_TOKENS WHERE TOKEN = ?", (token,))
        if cur.fetchone():
            return jsonify({"message": "Logout já feito com esse token", "error": True}), 401

        cur.execute("INSERT INTO BLACKLIST_TOKENS (TOKEN) VALUES (?)", (token,))
        con.commit()

        agendar_exclusao_token(token, 3)

        return jsonify({"message": "Logout bem-sucedido!", "error": False}), 200

    except Exception as e:
        return jsonify({"message": "Erro interno de servidor", "error1": f"{e}"}), 500

    finally:
        cur.close()


@app.route("/planos/criar/<int:id_usuario>", methods=["POST"])
def criar_plano(id_usuario):
    # Cria um plano vazio para depois associar exercícios

    # Pelo menos personal
    verificacao = informar_verificacao(2)
    if verificacao:
        return verificacao

    id_personal = informar_verificacao(trazer_pl=True)
    id_personal = id_personal["id_usuario"]

    data = request.get_json()
    horas_dia = data.get("horas_dia")  # horas por dia
    objetivo = data.get("objetivo_plano")

    try:
        horas_dia = int(horas_dia)
    except (TypeError, ValueError):
        return jsonify({"message": "horas_dia precisa ser um inteiro", "error": True})
    if len(objetivo) > 1000:
        return jsonify({"message": "Limite de caracteres de objetivo de plano excedido (1000)", "error": True})

    cur = con.cursor()
    try:
        # Verificar tentativa de criar um plano para alguém que não é cliente
        cur.execute("SELECT TIPO FROM USUARIOS WHERE ID_USUARIO = ?", (id_usuario, ))
        tipo_usuario = cur.fetchone()
        if tipo_usuario[0] > 1:
            return jsonify({"message": "Esse usuário não pode ter planos", "error": True}), 401

        cur.execute("""INSERT INTO PLANOS(ID_USUARIO_ALUNO, ID_USUARIO_PERSONAL, HORAS_DIA, OBJETIVO_PLANO) 
        VALUES(?,?,?,?)""", (id_usuario, id_personal, horas_dia, objetivo))
        con.commit()
        return({"message": "Plano criado com sucesso!", "error": False}), 200

    except Exception:
        print("Erro em /planos/criar/<int:id_usuario>")
        raise
    finally:
        try:
            cur.close()
        except Exception:
            pass


@app.route("/planos/adicionar-exercicio/<int:id_plano>", methods=["POST"])
def colocar_novo_exercicio_no_plano(id_plano):
    verificacao = informar_verificacao(2)
    if verificacao:
        return verificacao
    data = request.get_json()
    exercicio = data.get('id_exercicio')
    series = data.get('series')
    dia = data.get("dia")  # segunda-feira, terça-feira, etc.

    try:
        series = int(series)
        exercicio = int(exercicio)
    except (TypeError, ValueError):
        return jsonify({"message": "A quantidade de séries e o id_exercicio precisam ser em números inteiros",
                        "error": True}), 400

    if series < 1:
        series = 1

    cur = con.cursor()
    try:
        # Verificar se o plano existe
        cur.execute("SELECT 1 FROM PLANOS WHERE ID_PLANO = ?", (id_plano, ))
        if not cur.fetchone():
            return jsonify({"message": "Plano não encontrado", "error": True}), 404

        # Verificar se o exercício existe
        cur.execute("SELECT 1 FROM EXERCICIOS WHERE ID_EXERCICIO = ?", (exercicio, ))
        if not cur.fetchone():
            return jsonify({"message": "Exercício que foi tentado adicionar não encontrado", "error": True}), 404

        cur.execute("""INSERT INTO DIA_DA_SEMANA_EXERCICIOS_PLANO(ID_PLANO, ID_EXERCICIO, DIA_DA_SEMANA) 
        VALUES(?,?,?) RETURNING ID_DIA_EXERCICIO""", (id_plano, exercicio, dia, ))

        id_dia_exercicio = cur.fetchone()[0]

        print(f"ID_DIA_EXERCICIO = {id_dia_exercicio}")
        # Criar os registros das séries
        x = 0
        while x < series:
            cur.execute("INSERT INTO SERIES_EXERCICIO_DIA(ID_DIA_EXERCICIO) VALUES(?)", (id_dia_exercicio,))
            x += 1  # adiciona até x == series

        con.commit()
        return jsonify({"message": "Exercício adicionado ao plano com sucesso!", "error:": False}), 200

    except Exception:
        print("Erro em /planos/adicionar-exercicio/<int:id_plano>")
        raise
    finally:
        try:
            cur.close()
        except Exception:
            pass


@app.route('/planos/editar/<int:id_plano>', methods=["PUT"])
def editar_plano(id_plano):
    verificacao = informar_verificacao(2)
    if verificacao:
        return verificacao

    data = request.get_json()
    horas_dia = data.get('horas_dia')
    objetivo = data.get('objetivo_plano')

    try:
        horas_dia = int(horas_dia)
    except (TypeError, ValueError):
        return jsonify({"message": "horas_dia precisa ser um inteiro", "error": True})
    if len(objetivo) > 1000:
        return jsonify({"message": "Limite de caracteres de objetivo de plano excedido (1000)", "error": True})

    cur = con.cursor()
    try:
        cur.execute("SELECT HORAS_DIA, OBJETIVO_PLANO FROM PLANOS WHERE ID_PLANO = ?", (id_plano,))
        dados = cur.fetchone()

        if not dados:
            return jsonify({"message": "Plano não encontrado", "error": True}), 404

        # Substituindo dados pelos que já existem no banco de dados caso não foram recebidos
        horas_dia = dados[0] if not horas_dia else horas_dia
        objetivo = dados[1] if not objetivo else objetivo

        cur.execute("""UPDATE PLANOS SET HORAS_DIA = ?, OBJETIVO_PLANO = ?""", (horas_dia, objetivo,))
        con.commit()
        return jsonify({"message": "Plano editado com sucesso", "error": False}), 200
    except Exception:
        print("Erro em /planos/editar/<int:id_plano>")
        raise
    finally:
        try:
            cur.close()
        except Exception:
            pass


@app.route('/planos/excluir/<int:id_plano>', methods=["DELETE"])
def excluir_plano(id_plano):
    verificacao = informar_verificacao(2)
    if verificacao:
        return verificacao

    cur = con.cursor()
    try:
        cur.execute("SELECT 1 FROM PLANOS WHERE ID_PLANO = ?", (id_plano,))
        if not cur.fetchone():
            return jsonify({"message": "Plano não encontrado", "error": True}), 404

        # Excluindo primeiro das tabelas que usam a chave primária do plano como chave estrangeira
        cur.execute("""DELETE FROM SERIES_EXERCICIO_DIA 
        WHERE ID_DIA_EXERCICIO IN
         (SELECT ID_DIA_EXERCICIO FROM DIA_DA_SEMANA_EXERCICIOS_PLANO WHERE ID_PLANO = ?)""",(id_plano, ))
        cur.execute("DELETE FROM DIA_DA_SEMANA_EXERCICIOS_PLANO WHERE ID_PLANO = ?", (id_plano, ))

        cur.execute("DELETE FROM PLANOS WHERE ID_PLANO = ?", (id_plano, ))

        return jsonify({"message": "Plano excluído com sucesso!", "error": False})

    except Exception:
        print("Erro ao excluir plano")
        raise
    finally:
        try:
            cur.close()
        except Exception:
            pass


# Visualiza todos os exercícios do plano do usuário e os dias de cada um
@app.route('/planos/<int:id_usuario>', methods=["GET"])
def visualizar_plano_de_aluno(id_usuario):
    verificacao = informar_verificacao(2)
    if verificacao:
        return verificacao

    cur = con.cursor()
    try:
        # Ver se existe
        cur.execute("SELECT 1 FROM USUARIOS WHERE ID_USUARIO = ?", (id_usuario, ))
        if not cur.fetchone():
            return jsonify({"message": "Esse usuário não existe", "error": True}), 404

        cur.execute("SELECT ID_PLANO FROM PLANOS WHERE ID_USUARIO_ALUNO = ?", (id_usuario,))
        ids_planos = cur.fetchall()  # ex: [(1,), (2,), ...]

        planos = {}
        for (id_plano,) in ids_planos:  # descompacta tuple para int
            cur.execute("""
                SELECT e.ID_EXERCICIO, e.NOME, e.DESCRICAO, e.NIVEL_DIFICULDADE, e.VIDEO, D.DIA_DA_SEMANA
                FROM EXERCICIOS e
                LEFT JOIN DIA_DA_SEMANA_EXERCICIOS_PLANO D ON D.ID_EXERCICIO = e.ID_EXERCICIO
                WHERE D.ID_PLANO = ?
                ORDER BY D.DIA_DA_SEMANA ASC
            """, (id_plano,))
            plano = cur.fetchall()  # lista de tuplas (exercícios)
            planos[id_plano] = plano

        return jsonify({"planos": planos, "error": False})

    except Exception:
        print("Erro em visualizar_plano_de_aluno")
        raise
    finally:
        try:
            cur.close()
        except Exception:
            pass


@app.route('/planos/retirar-exercicio/<int:id_plano>', methods=["DELETE"])
def retirar_exercicio_do_plano(id_plano):
    verificacao = informar_verificacao(2)
    if verificacao:
        return verificacao
    data = request.get_json()
    exercicio = data.get('id_exercicio')

    try:
        exercicio = int(exercicio)
    except (TypeError, ValueError):
        return jsonify({"message": "O exercício precisa ser em número inteiro",
                        "error": True}), 400

    cur = con.cursor()
    try:
        # Verificar se o plano existe
        cur.execute("SELECT 1 FROM PLANOS WHERE ID_PLANO = ?", (id_plano,))
        if not cur.fetchone():
            return jsonify({"message": "Plano não encontrado", "error": True}), 404

        # Verificar se o exercício existe
        cur.execute("SELECT 1 FROM EXERCICIOS WHERE ID_EXERCICIO = ?", (exercicio,))
        if not cur.fetchone():
            return jsonify({"message": "Exercício que foi tentado retirar não encontrado", "error": True}), 404

        cur.execute("""DELETE FROM DIA_DA_SEMANA_EXERCICIOS_PLANO 
        WHERE ID_EXERCICIO = ? AND ID_PLANO = ?""", (exercicio, id_plano,))
        con.commit()
        return jsonify({"message": "Exercício adicionado ao plano com sucesso!", "error:": False}), 200

    except Exception:
        print("Erro em /planos/adicionar-exercicio/<int:id_plano>")
        raise
    finally:
        try:
            cur.close()
        except Exception:
            pass


# Traz todos os dados de todos os exercícios
@app.route("/exercicios/<int:resumir>", methods=["GET"])  # Se resumir não for 0, trazer apenas nome e IDs
def ver_biblioteca_de_exercicios(resumir=0):
    verificacao = informar_verificacao()
    if verificacao:
        return verificacao

    cur = con.cursor()
    try:
        if resumir == 0:
            cur.execute("SELECT ID_EXERCICIO, NOME, DESCRICAO, NIVEL_DIFICULDADE, VIDEO FROM EXERCICIOS")
            subtitulos = ["ID_EXERCICIO", "NOME_EXERCICIO", "DESCRICAO", "DIFICULDADE", "VIDEO"]
        else:
            cur.execute("SELECT ID_EXERCICIO, NOME FROM EXERCICIOS")
            subtitulos = ["ID_EXERCICIO", "NOME_EXERCICIO"]

        exercicios = cur.fetchall()
        dados_json = [dict(zip(subtitulos, registro)) for registro in exercicios]
        return jsonify({"exercicios": dados_json, "error": False})
    except Exception:
        print("erro em /exercícios")
        raise
    finally:
        try:
            cur.close()
        except Exception:
            pass


@app.route("/exercicios/detalhes/<int:id_exercicio>", methods=["GET"])  # Se resumir não for 0, trazer apenas nome e IDs
def ver_exercicios(id_exercicio):
    verificacao = informar_verificacao()
    if verificacao:
        return verificacao

    cur = con.cursor()
    try:
        # Verificar se existe
        cur.execute("SELECT 1 FROM EXERCICIOS WHERE ID_EXERCICIO = ?", (id_exercicio, ))
        if not cur.fetchone():
            return jsonify({"message": "Exercício não encontrado", "error": True}), 404

        cur.execute("""SELECT ID_EXERCICIO, NOME, DESCRICAO, NIVEL_DIFICULDADE, VIDEO FROM EXERCICIOS 
        WHERE ID_EXERCICIO = ?""", (id_exercicio, ))
        subtitulos = ["ID_EXERCICIO", "NOME_EXERCICIO", "DESCRICAO", "DIFICULDADE", "VIDEO"]
        exercicios = cur.fetchall()

        # Pegar os grupos musculares
        cur.execute("SELECT ID_GRUPO_MUSCULAR FROM GRUPO_M_EXERCICIO WHERE ID_EXERCICIO = ?", (id_exercicio, ))
        g_musc = cur.fetchall()
        g_musc2 = []
        for g_musc0 in g_musc:
            g_musc2.append(g_musc0[0])

        dados_json = [dict(zip(subtitulos, registro)) for registro in exercicios]
        dados_json[0]["GRUPOS_MUSCULARES"] = g_musc2

        return jsonify({"exercicios": dados_json, "error": False})
    except Exception:
        print("erro em /exercícios")
        raise
    finally:
        try:
            cur.close()
        except Exception:
            pass


@app.route("/exercicios/criar/", methods=["POST"])
def criar_exercicio():
    # Responsável por criar exercícios, não por associar exercícios a um plano

    # Verificar se é pelo menos personal
    verificacao = informar_verificacao(2)
    if verificacao:
        return verificacao

    data = request.get_json()
    nome = data.get('nome')
    grupos_musculares = data.get('gruposMuscularesSelecionados', [])  # ["exercicio1", "exercicio2"]
    descricao = data.get('descricao')
    nivel_dificuldade = data.get('dificuldade')
    video = data.get('video')

    if not all([nome, grupos_musculares, descricao, nivel_dificuldade]):
        return jsonify({"message": "Todos os campos são obrigatórios, exceto vídeo", "error": True})

    # Verificações de formatação e comprimento de dados
    if len(nome) > 255:
        return jsonify({"message": "Comprimento de nome excedido (255)", "error": True})
    if video:
        if len(video) > 255:
            return jsonify({"message": "Comprimento de vídeo excedido (255)", "error": True})
    if len(descricao) > 1000:
        return jsonify({"message": "Comprimento de descrição excedido (1000)", "error": True})
    try:
        nivel_dificuldade = int(nivel_dificuldade)
    except (TypeError, ValueError):
        return jsonify({"message": "nivel_dificuldade precisa ser um inteiro (1 = fácil, 2 = médio, 3 = difícil)",
                        "error": True})

    cur = con.cursor()
    try:
        cur.execute("""INSERT INTO EXERCICIOS(NOME, DESCRICAO, NIVEL_DIFICULDADE, VIDEO) 
        VALUES(?,?,?,?) RETURNING ID_EXERCICIO""", (nome, descricao, nivel_dificuldade, video, ))

        id_exercicio = cur.fetchone()
        if not id_exercicio:
            return jsonify({"message": "Erro ao recuperar id de exercício", "error": True}), 500

        for grupo in grupos_musculares:
            cur.execute("INSERT INTO GRUPO_M_EXERCICIO(ID_GRUPO_MUSCULAR, ID_EXERCICIO) "
                        "VALUES(?,?)", (grupo, id_exercicio[0], ))

        con.commit()
        return jsonify({"message": "Exercício criado com sucesso!", "error": False}), 200

    except Exception:
        print("Erro em criar exercício")
        raise
    finally:
        try:
            cur.close()
        except Exception:
            pass


@app.route('/exercicios/excluir/<int:id_exercicio>', methods=["DELETE"])
def excluir_exercicio(id_exercicio):
    verificacao = informar_verificacao(2)
    if verificacao:
        return verificacao

    cur = con.cursor()
    try:
        # Ver se existe
        cur.execute("SELECT 1 FROM EXERCICIOS WHERE ID_EXERCICIO = ?", (id_exercicio, ))
        if not cur.fetchone():
            return jsonify({"message": "Exercício não encontrado", "error": True}), 404

        # Excluir primeiro das outras tabelas que usam ID_EXERCICIO
        cur.execute("DELETE FROM GRUPO_M_EXERCICIO WHERE ID_EXERCICIO = ?", (id_exercicio, ))
        cur.execute("DELETE FROM DIA_DA_SEMANA_EXERCICIOS_PLANO WHERE ID_EXERCICIO = ?", (id_exercicio, ))

        cur.execute("DELETE FROM EXERCICIOS WHERE ID_EXERCICIO = ?", (id_exercicio, ))
        con.commit()
        return jsonify({"message": "Exercício excluído com sucesso!", "error": False}), 200
    finally:
        try:
            cur.close()
        except Exception:
            pass


@app.route("/exercicios/editar/<int:id_exercicio>", methods=["PUT"])
def editar_exercicio(id_exercicio):
    verificacao = informar_verificacao(2)
    if verificacao:
        return verificacao

    data = request.get_json()
    nome = data.get('nome')
    descricao = data.get('descricao')
    video = data.get('video')
    dificuldade = data.get('dificuldade')
    grupos_musculares = data.get('gruposMuscularesSelecionados', [])

    if dificuldade:
        try:
            dificuldade = int(dificuldade)
        except (TypeError, ValueError):
            return jsonify({"message": "dificuldade precisa ser um inteiro", "error": True}), 400

    cur = con.cursor()
    try:
        cur.execute("SELECT NOME, DESCRICAO, VIDEO, NIVEL_DIFICULDADE FROM EXERCICIOS "
                    "WHERE ID_EXERCICIO = ?", (id_exercicio, ))
        dados = cur.fetchone()

        if not dados:
            return jsonify({"message": "Exercício não encontrado", "error": True}), 404

        if grupos_musculares:
            # Excluir todos os registros desse exercício que o relacionam aos seus grupos musculares
            cur.execute("DELETE FROM GRUPO_M_EXERCICIO WHERE ID_EXERCICIO = ?", (id_exercicio,))

            # Adicionar os novos registros
            for grupo in grupos_musculares:
                cur.execute("INSERT INTO GRUPO_M_EXERCICIO(ID_GRUPO_MUSCULAR, ID_EXERCICIO) "
                            "VALUES(?,?)", (grupo, id_exercicio,))

        # Substituindo dados pelos que já existem no banco de dados caso não foram recebidos
        nome = dados[0] if not nome else nome
        descricao = dados[1] if not descricao else descricao
        video = dados[2] if not video else video
        dificuldade = dados[3] if not dificuldade else dificuldade

        cur.execute("""UPDATE EXERCICIOS SET NOME = ?, DESCRICAO = ?, VIDEO = ?, NIVEL_DIFICULDADE = ? 
        WHERE ID_EXERCICIO = ?""", (nome, descricao, video, dificuldade, id_exercicio, ))
        con.commit()
        return jsonify({"message": "Exercício editado com sucesso", "error": False}), 200
    except Exception:
        print("Erro em /exercicios/editar/<int:id_exercicio>")
        raise
    finally:
        try:
            cur.close()
        except Exception:
            pass


@app.route('/grupos_musculares', methods=['GET'])
def trazer_grupos_musculares():
    # Verificar se é pelo menos aluno
    verificacao = informar_verificacao()
    if verificacao:
        return verificacao
    cur = con.cursor()
    try:
        cur.execute("SELECT * FROM GRUPOS_MUSCULARES")
        grupos_musculares = cur.fetchall()
        subtitulos = ["ID_GRUPO_MUSCULAR", "NOME_MUSCULOS", "CAMINHO_IMAGEM", "FONTE_IMAGEM"]

        dados_json = [dict(zip(subtitulos, registro)) for registro in grupos_musculares]
        return jsonify({"grupos_musculares": dados_json, "error": False})
    except Exception:
        print("Erro em /grupos_musculares")
        raise

    finally:
        try:
            cur.close()
        except Exception:
            pass

    # exercicios = data.get('exerciciosSelecionados', []).split(',')

    # cur.execute("""
    #             SELECT t.id_tag, t.nome_tag
    #             FROM LIVRO_TAGS lt
    #             LEFT JOIN TAGS t ON lt.ID_TAG = t.ID_TAG
    #             WHERE lt.ID_LIVRO = ?
    #         """, (id,))
    #
    # tags = cur.fetchall()
    # selected_tags = [{'id': tag[0], 'nome': tag[1]} for tag in tags]
