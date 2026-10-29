import math
import os
import re
import secrets
import sqlite3
from datetime import date, datetime, timedelta, timezone
from functools import wraps
from urllib.parse import urlparse
from werkzeug.security import generate_password_hash, check_password_hash

from flask import (Flask, abort, flash, g, jsonify, redirect, render_template,
                   request, session, url_for)
from werkzeug.middleware.proxy_fix import ProxyFix

import oauth_google
from criar_banco import (CAMINHO_PADRAO, agora_texto, autorizar_email,
                         criar_ou_atualizar_banco)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def carregar_chave_secreta():
    """Chave que assina a sessão de login: variável SECRET_KEY ou arquivo .secret_key."""
    chave = os.environ.get('SECRET_KEY')
    if chave:
        return chave
    caminho = os.path.join(BASE_DIR, '.secret_key')
    if not os.path.exists(caminho):
        with open(caminho, 'w') as arquivo:
            arquivo.write(secrets.token_hex(32))
    with open(caminho) as arquivo:
        return arquivo.read().strip()


app = Flask(__name__)
app.config['DATABASE'] = CAMINHO_PADRAO
app.config['SECRET_KEY'] = carregar_chave_secreta()
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 8 * 60 * 60  # sessão válida por 8 horas

# Em hospedagens com proxy (HTTPS na frente do app), defina TRUST_PROXY=1 para que o IP
# dos visitantes e o endereço de retorno do Google (https) saiam corretos.
if os.environ.get('TRUST_PROXY') == '1':
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

COLUNAS = 'id, nome, quantidade, preco, fornecedor, observacao, data'
MINUTOS_ONLINE = 5          # quem teve atividade nesse intervalo aparece como "online"
REGISTRO_RECENTE = 50       # quantidade de eventos exibidos no histórico de acessos
EMAIL_VALIDO = re.compile(r'[^@\s]+@[^@\s]+\.[^@\s]+')
SENHA_MINIMA = 8           # tamanho mínimo da senha no login com e-mail e senha

# ------------------------------------------------------------------ utilidades


def conectar():
    return sqlite3.connect(app.config['DATABASE'])


def hoje():
    """Data de hoje no horário de Brasília (usa a data do servidor se não houver fuso)."""
    try:
        from zoneinfo import ZoneInfo
        return datetime.now(ZoneInfo('America/Sao_Paulo')).date()
    except Exception:
        return date.today()


@app.template_filter('data_br')
def data_br(valor):
    """'2026-10-21' -> '21/10/2026' (None se a data não existir ou for inválida)."""
    try:
        return date.fromisoformat(valor).strftime('%d/%m/%Y')
    except (TypeError, ValueError):
        return None


@app.template_filter('datahora_br')
def datahora_br(valor):
    """'2026-10-21 14:05:00' (UTC) -> '21/10/2026 11:05' (horário de Brasília)."""
    if not valor:
        return '-'
    try:
        momento = datetime.strptime(valor, '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
    except ValueError:
        return '-'
    try:
        from zoneinfo import ZoneInfo
        fuso = ZoneInfo('America/Sao_Paulo')
    except Exception:
        fuso = timezone(timedelta(hours=-3))
    return momento.astimezone(fuso).strftime('%d/%m/%Y %H:%M')


@app.template_filter('navegador_resumo')
def navegador_resumo(agente):
    """Resume o texto técnico do navegador, ex.: 'Chrome em Windows'."""
    agente = agente or ''
    navegador = next((nome for chave, nome in (('Edg/', 'Edge'), ('OPR/', 'Opera'), ('Firefox/', 'Firefox'),
                                               ('Chrome/', 'Chrome'), ('Safari/', 'Safari')) if chave in agente),
                     'Navegador desconhecido')
    sistema = next((nome for chave, nome in (('Android', 'Android'), ('iPhone', 'iOS'), ('iPad', 'iOS'),
                                             ('Windows', 'Windows'), ('Mac OS', 'macOS'), ('Linux', 'Linux'))
                    if chave in agente), None)
    return f'{navegador} em {sistema}' if sistema else navegador


def ip_do_cliente():
    return request.remote_addr or 'desconhecido'


def navegador_do_cliente():
    return (request.headers.get('User-Agent') or '')[:300]


def registrar_acesso(conexao, evento, email, nome):
    """Guarda no histórico: 'entrada', 'saida' ou 'negado'."""
    conexao.execute(
        'INSERT INTO acessos (quando, evento, email, nome, ip, navegador) VALUES (?, ?, ?, ?, ?, ?)',
        (agora_texto(), evento, email, nome, ip_do_cliente(), navegador_do_cliente()))


def emails_admin():
    """E-mails definidos em ADMIN_EMAILS (separados por vírgula): sempre entram como administradores."""
    return {e.strip().lower() for e in os.environ.get('ADMIN_EMAILS', '').split(',') if e.strip()}


def config_google():
    return os.environ.get('GOOGLE_CLIENT_ID', '').strip(), os.environ.get('GOOGLE_CLIENT_SECRET', '').strip()


def google_configurado():
    return all(config_google())


# ---------------------------------------------------------------- segurança


def token_csrf():
    if 'csrf' not in session:
        session['csrf'] = secrets.token_hex(16)
    return session['csrf']


app.jinja_env.globals['csrf_token'] = token_csrf


@app.before_request
def carregar_conta():
    """Identifica quem está logado (a cada requisição) e atualiza a "última atividade"."""
    g.conta = None
    sid = session.get('sid')
    if not sid:
        return
    conexao = conectar()
    linha = conexao.execute(
        'SELECT c.id, c.email, c.nome, c.papel, s.ultima_atividade FROM sessoes s '
        'JOIN contas c ON c.email = s.email '
        'WHERE s.sid = ? AND s.encerrada = 0 AND c.ativo = 1', (sid,)).fetchone()
    if linha is None:
        # Sessão encerrada, conta desativada ou removida: obriga a entrar de novo
        session.clear()
    else:
        g.conta = {'id': linha[0], 'email': linha[1], 'nome': linha[2] or linha[1], 'papel': linha[3]}
        limite = (datetime.now(timezone.utc) - timedelta(seconds=60)).strftime('%Y-%m-%d %H:%M:%S')
        if linha[4] < limite:  # grava no máximo uma vez por minuto
            conexao.execute('UPDATE sessoes SET ultima_atividade = ?, ip = ?, navegador = ? WHERE sid = ?',
                            (agora_texto(), ip_do_cliente(), navegador_do_cliente(), sid))
            conexao.commit()
    conexao.close()


@app.before_request
def verificar_csrf():
    if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
        enviado = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token') or ''
        esperado = session.get('csrf', '')
        # O token precisa existir na sessão e coincidir com o enviado (vazio nunca vale)
        if not esperado or not enviado or not secrets.compare_digest(enviado, esperado):
            abort(400)


@app.context_processor
def injetar_conta():
    return {'conta': g.get('conta')}


@app.after_request
def nao_guardar_em_cache(resposta):
    # Impede que páginas internas fiquem visíveis pelo botão "voltar" após o logout
    if g.get('conta'):
        resposta.headers['Cache-Control'] = 'no-store'
    return resposta


def login_required(funcao):
    @wraps(funcao)
    def interna(*args, **kwargs):
        if g.conta is None:
            if request.path.startswith('/api/'):
                return jsonify(ok=False, erro='Não autenticado.'), 401
            return redirect(url_for('login', next=request.full_path.rstrip('?')))
        return funcao(*args, **kwargs)
    return interna


def admin_required(funcao):
    @wraps(funcao)
    @login_required
    def interna(*args, **kwargs):
        if g.conta['papel'] != 'admin':
            abort(403)
        return funcao(*args, **kwargs)
    return interna


def destino_seguro(destino):
    """Aceita apenas caminhos internos do site (evita redirecionamento para outros sites)."""
    if destino and destino.startswith('/') and not destino.startswith('//') \
            and '\\' not in destino and not urlparse(destino).netloc:
        return destino
    return '/'


# --------------------------------------------------------------- validação


def validar_formulario(form):
    """Lê e valida os dados do item. Retorna (dados, erros).

    Obrigatórios: nome, quantidade, preço e data de entrada.
    Opcionais: fornecedor e observação.
    'erros' é um dicionário {campo: mensagem}, usado para indicar cada campo com problema.
    """
    erros = {}

    nome = form.get('nome', '').strip()
    fornecedor = form.get('fornecedor', '').strip()
    observacao = form.get('observacao', '').strip()

    if not nome:
        erros['nome'] = 'Informe o nome da peça.'

    quantidade = None
    try:
        quantidade = int(form.get('quantidade', ''))
        if quantidade < 0:
            erros['quantidade'] = 'A quantidade não pode ser negativa.'
    except ValueError:
        erros['quantidade'] = 'A quantidade deve ser um número inteiro.'

    preco = None
    try:
        preco = float(form.get('preco', '').replace(',', '.'))
        if not math.isfinite(preco):
            erros['preco'] = 'O preço deve ser um número válido.'
        elif preco < 0:
            erros['preco'] = 'O preço não pode ser negativo.'
    except ValueError:
        erros['preco'] = 'O preço deve ser um número válido.'

    data = form.get('data', '').strip()
    try:
        if date.fromisoformat(data) > hoje():
            erros['data'] = 'A data de entrada não pode ser futura.'
    except ValueError:
        erros['data'] = 'Informe uma data de entrada válida.'

    if erros:
        return None, erros

    return (nome, quantidade, preco, fornecedor, observacao, data), {}


# ------------------------------------------------- login com e-mail/senha e com o Google


def iniciar_sessao(conexao, email, nome, destino):
    """Abre a sessão da pessoa, registra a entrada e redireciona para o destino seguro.

    Usado tanto pelo login com e-mail e senha quanto pelo login com o Google, para que os
    dois caminhos gravem a sessão e o histórico exatamente da mesma forma.
    """
    sid = secrets.token_urlsafe(24)
    agora = agora_texto()
    conexao.execute('INSERT INTO sessoes (sid, email, ip, navegador, inicio, ultima_atividade) VALUES (?, ?, ?, ?, ?, ?)',
                    (sid, email, ip_do_cliente(), navegador_do_cliente(), agora, agora))
    conexao.execute('UPDATE contas SET nome = COALESCE(?, nome), ultimo_acesso = ? WHERE email = ?',
                    (nome, agora, email))
    registrar_acesso(conexao, 'entrada', email, nome)
    conexao.commit()
    conexao.close()

    session.clear()  # nova sessão após o login (não reaproveita a sessão anterior)
    session['sid'] = sid
    session.permanent = True
    return redirect(destino_seguro(destino))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Entrada com e-mail e senha. A entrada com o Google é feita por /auth/google."""
    if g.conta:
        return redirect('/')

    erro, email = None, ''
    if request.method == 'POST':
        destino = destino_seguro(request.form.get('next', ''))
        email = request.form.get('email', '').strip().lower()
        senha = request.form.get('senha', '')

        conexao = conectar()
        conta = conexao.execute(
            'SELECT email, nome, senha_hash, ativo FROM contas WHERE email = ?', (email,)).fetchone()
        if conta and conta[3] and conta[2] and check_password_hash(conta[2], senha):
            return iniciar_sessao(conexao, conta[0], conta[1], destino)

        if conta:  # tentativas erradas em contas existentes ficam no histórico como "negado"
            registrar_acesso(conexao, 'negado', email, conta[1])
            conexao.commit()
        conexao.close()
        # Mesma mensagem para e-mail inexistente, senha errada ou conta inativa (não revela contas)
        erro = 'E-mail ou senha inválidos, ou conta inativa.'
    else:
        destino = destino_seguro(request.args.get('next', ''))

    return render_template('login.html', erro=erro, email=email, destino=destino,
                           configurado=google_configurado())


@app.route('/solicitar-acesso', methods=['GET', 'POST'])
def solicitar_acesso():
    """Pedido de acesso para quem não tem conta: fica pendente até um administrador aprovar."""
    erro, enviado, nome, email = None, False, '', ''
    if request.method == 'POST':
        nome = request.form.get('nome', '').strip()
        email = request.form.get('email', '').strip().lower()
        senha = request.form.get('senha', '')
        confirmacao = request.form.get('confirmar_senha', '')

        if not nome:
            erro = 'Informe o seu nome.'
        elif not EMAIL_VALIDO.fullmatch(email):
            erro = 'Informe um e-mail válido.'
        elif len(senha) < SENHA_MINIMA:
            erro = f'A senha deve ter pelo menos {SENHA_MINIMA} caracteres.'
        elif senha != confirmacao:
            erro = 'A confirmação da senha não confere com a senha informada.'
        else:
            conexao = conectar()
            tem_conta = conexao.execute('SELECT 1 FROM contas WHERE email = ?', (email,)).fetchone()
            pedido = conexao.execute(
                'SELECT status FROM solicitacoes_acesso WHERE email = ?', (email,)).fetchone()
            if tem_conta:
                erro = ('Este e-mail já possui cadastro. Tente entrar; se não conseguir, '
                        'peça ajuda a um administrador.')
            elif pedido and pedido[0] == 'pendente':
                erro = 'Já existe um pedido pendente para este e-mail. Aguarde a análise do administrador.'
            else:
                valores = (nome, generate_password_hash(senha), agora_texto())
                if pedido:  # pedido recusado antes: reabre com os dados novos
                    conexao.execute(
                        "UPDATE solicitacoes_acesso SET nome = ?, senha_hash = ?, criado_em = ?, "
                        "status = 'pendente' WHERE email = ?", valores + (email,))
                else:
                    conexao.execute(
                        'INSERT INTO solicitacoes_acesso (email, nome, senha_hash, criado_em) '
                        'VALUES (?, ?, ?, ?)', (email,) + valores)
                conexao.commit()
                enviado = True
            conexao.close()

    return render_template('solicitar_acesso.html', erro=erro, enviado=enviado, nome=nome, email=email)


@app.route('/auth/google')
def entrar_com_google():
    """Passo 1: envia o usuário para a página de login do Google."""
    if g.conta:
        return redirect('/')
    client_id, _ = config_google()
    if not google_configurado():
        flash('O login com o Google ainda não foi configurado neste servidor.', 'erro')
        return redirect(url_for('login'))

    destino = destino_seguro(request.args.get('next', ''))
    csrf = token_csrf()
    estado = secrets.token_urlsafe(24)
    verificador = oauth_google.gerar_verificador()
    session['oauth'] = {'estado': estado, 'verificador': verificador, 'destino': destino}
    session['csrf'] = csrf

    redirect_uri = os.environ.get('OAUTH_REDIRECT_URI') or url_for('callback_google', _external=True)
    return redirect(oauth_google.url_de_autorizacao(client_id, redirect_uri, estado, verificador))


@app.route('/auth/google/callback')
def callback_google():
    """Passo 2: o Google devolve o usuário aqui, com um código de uso único."""
    dados_oauth = session.pop('oauth', None)

    def falha(mensagem):
        flash(mensagem, 'erro')
        return redirect(url_for('login'))

    if request.args.get('error'):
        return falha('O login com o Google foi cancelado.')
    if not dados_oauth or not secrets.compare_digest(request.args.get('state', ''), dados_oauth['estado']):
        return falha('Não foi possível confirmar a origem do login. Tente entrar novamente.')
    codigo = request.args.get('code', '')
    if not codigo:
        return falha('O Google não enviou o código de autorização. Tente novamente.')

    client_id, client_secret = config_google()
    redirect_uri = os.environ.get('OAUTH_REDIRECT_URI') or url_for('callback_google', _external=True)
    try:
        perfil = oauth_google.obter_perfil_google(client_id, client_secret, codigo,
                                                  dados_oauth['verificador'], redirect_uri)
    except oauth_google.ErroOAuth:
        return falha('Não foi possível concluir o login com o Google. Tente novamente em instantes.')

    email = str(perfil.get('email', '')).strip().lower()
    nome = str(perfil.get('name') or '').strip() or None
    verificado = perfil.get('email_verified') in (True, 'true')

    if not email or not verificado:
        conexao = conectar()
        registrar_acesso(conexao, 'negado', email or None, nome)
        conexao.commit()
        conexao.close()
        return falha('O Google não confirmou o e-mail desta conta. Use outra conta.')

    # Administradores definidos na configuração sempre têm acesso
    if email in emails_admin():
        autorizar_email(app.config['DATABASE'], email, 'admin', nome)

    conexao = conectar()
    conta = conexao.execute('SELECT ativo FROM contas WHERE email = ?', (email,)).fetchone()
    if conta is None or not conta[0]:
        registrar_acesso(conexao, 'negado', email, nome)
        conexao.commit()
        conexao.close()
        return falha('Este e-mail não está autorizado a acessar o sistema. Peça a um administrador para liberá-lo.')

    return iniciar_sessao(conexao, email, nome, dados_oauth['destino'])


@app.route('/logout', methods=['POST'])
def logout():
    if g.conta:
        conexao = conectar()
        conexao.execute('UPDATE sessoes SET encerrada = 1 WHERE sid = ?', (session.get('sid'),))
        registrar_acesso(conexao, 'saida', g.conta['email'], g.conta['nome'])
        conexao.commit()
        conexao.close()
    session.clear()
    flash('Você saiu do sistema.', 'sucesso')
    return redirect(url_for('login'))


@app.route('/api/me')
@login_required
def api_me():
    return jsonify(ok=True, email=g.conta['email'], nome=g.conta['nome'], papel=g.conta['papel'])


# ----------------------------------------------------- área do administrador


@app.route('/admin')
@admin_required
def admin():
    limite_online = (datetime.now(timezone.utc) - timedelta(minutes=MINUTOS_ONLINE)).strftime('%Y-%m-%d %H:%M:%S')
    conexao = conectar()
    online = conexao.execute(
        'SELECT COALESCE(c.nome, s.email), s.email, COALESCE(c.papel, \'usuario\'), s.ip, s.navegador, '
        's.inicio, s.ultima_atividade '
        'FROM sessoes s LEFT JOIN contas c ON c.email = s.email '
        'WHERE s.encerrada = 0 AND s.ultima_atividade >= ? ORDER BY s.ultima_atividade DESC',
        (limite_online,)).fetchall()
    historico = conexao.execute(
        'SELECT quando, evento, COALESCE(nome, email, \'-\'), email, ip, navegador FROM acessos '
        'ORDER BY id DESC LIMIT ?', (REGISTRO_RECENTE,)).fetchall()
    contas = conexao.execute(
        'SELECT id, email, nome, papel, ativo, ultimo_acesso FROM contas ORDER BY papel, email').fetchall()
    pendentes = conexao.execute(
        "SELECT id, nome, email, criado_em FROM solicitacoes_acesso WHERE status = 'pendente' "
        'ORDER BY criado_em').fetchall()
    conexao.close()
    return render_template('admin.html', online=online, historico=historico, contas=contas, pendentes=pendentes,
                           fixos=emails_admin(), minutos_online=MINUTOS_ONLINE,
                           limite_historico=REGISTRO_RECENTE)


@app.route('/admin/usuarios', methods=['POST'])
@admin_required
def admin_autorizar():
    email = request.form.get('email', '').strip().lower()
    papel = request.form.get('papel', 'usuario')
    if not EMAIL_VALIDO.fullmatch(email):
        flash('Informe um e-mail válido para autorizar.', 'erro')
    elif papel not in ('admin', 'usuario'):
        flash('Escolha um papel válido.', 'erro')
    else:
        autorizar_email(app.config['DATABASE'], email, papel)
        flash(f'{email} autorizado como {"administrador" if papel == "admin" else "usuário"}.', 'sucesso')
    return redirect(url_for('admin'))


def _conta_alteravel(conexao, id):
    """Busca a conta e confere se o admin pode alterá-la. Retorna (conta, mensagem_de_erro)."""
    conta = conexao.execute('SELECT id, email, papel, ativo FROM contas WHERE id = ?', (id,)).fetchone()
    if conta is None:
        abort(404)
    if conta[1] == g.conta['email']:
        return None, 'Você não pode alterar a própria conta.'
    if conta[1] in emails_admin():
        return None, 'Este administrador é definido pela configuração (ADMIN_EMAILS) e não pode ser alterado aqui.'
    return conta, None


@app.route('/admin/usuarios/<int:id>/ativo', methods=['POST'])
@admin_required
def admin_alternar_ativo(id):
    conexao = conectar()
    conta, erro = _conta_alteravel(conexao, id)
    if erro:
        flash(erro, 'erro')
    else:
        novo = 0 if conta[3] else 1
        conexao.execute('UPDATE contas SET ativo = ? WHERE id = ?', (novo, id))
        if not novo:  # desativar também derruba as sessões abertas dessa pessoa
            conexao.execute('UPDATE sessoes SET encerrada = 1 WHERE email = ?', (conta[1],))
        conexao.commit()
        flash(f'Acesso de {conta[1]} {"reativado" if novo else "desativado"}.', 'sucesso')
    conexao.close()
    return redirect(url_for('admin'))


@app.route('/admin/usuarios/<int:id>/papel', methods=['POST'])
@admin_required
def admin_alternar_papel(id):
    conexao = conectar()
    conta, erro = _conta_alteravel(conexao, id)
    if erro:
        flash(erro, 'erro')
    else:
        novo = 'usuario' if conta[2] == 'admin' else 'admin'
        conexao.execute('UPDATE contas SET papel = ? WHERE id = ?', (novo, id))
        conexao.commit()
        flash(f'{conta[1]} agora é {"administrador" if novo == "admin" else "usuário comum"}.', 'sucesso')
    conexao.close()
    return redirect(url_for('admin'))


@app.route('/admin/solicitacoes/<int:id>/aprovar', methods=['POST'])
@admin_required
def admin_aprovar_solicitacao(id):
    """Libera o pedido: cria a conta com o papel escolhido e a senha que a pessoa cadastrou."""
    papel = request.form.get('papel', 'usuario')
    conexao = conectar()
    pedido = conexao.execute(
        "SELECT email, nome, senha_hash FROM solicitacoes_acesso WHERE id = ? AND status = 'pendente'",
        (id,)).fetchone()
    conexao.close()

    if pedido is None:
        flash('Este pedido não existe mais ou já foi respondido.', 'erro')
    elif papel not in ('admin', 'usuario'):
        flash('Escolha um papel válido.', 'erro')
    else:
        email, nome, senha_hash = pedido
        autorizar_email(app.config['DATABASE'], email, papel, nome)
        conexao = conectar()
        conexao.execute('UPDATE contas SET senha_hash = ? WHERE email = ?', (senha_hash, email))
        # A senha já foi copiada para a conta; o pedido guarda só o registro da decisão
        conexao.execute("UPDATE solicitacoes_acesso SET status = 'aprovada', senha_hash = NULL WHERE id = ?", (id,))
        conexao.commit()
        conexao.close()
        flash(f'Pedido de {email} aprovado como {"administrador" if papel == "admin" else "usuário"}.', 'sucesso')
    return redirect(url_for('admin'))


@app.route('/admin/solicitacoes/<int:id>/recusar', methods=['POST'])
@admin_required
def admin_recusar_solicitacao(id):
    conexao = conectar()
    cursor = conexao.execute(
        "UPDATE solicitacoes_acesso SET status = 'recusada', senha_hash = NULL WHERE id = ? AND status = 'pendente'",
        (id,))
    conexao.commit()
    recusados = cursor.rowcount
    conexao.close()
    if recusados:
        flash('Pedido recusado.', 'sucesso')
    else:
        flash('Este pedido não existe mais ou já foi respondido.', 'erro')
    return redirect(url_for('admin'))


# ------------------------------------------------------------------ estoque


@app.route('/')
@login_required
def home():
    # Pega o termo de busca enviado pelo usuário (se houver)
    termo_busca = request.args.get('busca', '').strip()

    conexao = conectar()
    cursor = conexao.cursor()

    if termo_busca:
        # Filtra no banco de dados usando LIKE para buscar partes do nome
        cursor.execute(f'SELECT {COLUNAS} FROM pecas WHERE nome LIKE ?',
                       ('%' + termo_busca + '%',))
    else:
        cursor.execute(f'SELECT {COLUNAS} FROM pecas')

    pecas_banco = cursor.fetchall()
    conexao.close()

    total_tipos = len(pecas_banco)
    total_unidades = sum(p[2] for p in pecas_banco)
    valor_total_estoque = sum(p[2] * p[3] for p in pecas_banco)

    return render_template('index.html',
                           pecas=pecas_banco,
                           total_tipos=total_tipos,
                           total_unidades=total_unidades,
                           valor_total_estoque=valor_total_estoque,
                           termo_busca=termo_busca)


@app.route('/cadastrar', methods=['GET', 'POST'])
@login_required
def cadastrar():
    if request.method == 'POST':
        dados, erros = validar_formulario(request.form)
        if erros:
            # Reexibe o formulário com as mensagens e os valores digitados
            return render_template('formulario.html', modo='cadastro', erros=erros,
                                   form=request.form, hoje=hoje().isoformat()), 400

        conexao = conectar()
        conexao.execute(
            'INSERT INTO pecas (nome, quantidade, preco, fornecedor, observacao, data) '
            'VALUES (?, ?, ?, ?, ?, ?)', dados)
        conexao.commit()
        conexao.close()

        flash('Peça cadastrada com sucesso.', 'sucesso')
        return redirect('/')

    return render_template('formulario.html', modo='cadastro', erros={},
                           form={'data': hoje().isoformat()}, hoje=hoje().isoformat())


@app.route('/editar/<int:id>', methods=['GET', 'POST'])
@login_required
def editar(id):
    conexao = conectar()
    peca = conexao.execute(f'SELECT {COLUNAS} FROM pecas WHERE id = ?', (id,)).fetchone()
    if peca is None:
        conexao.close()
        abort(404)

    if request.method == 'POST':
        dados, erros = validar_formulario(request.form)
        if erros:
            conexao.close()
            return render_template('formulario.html', modo='edicao', peca_id=id, erros=erros,
                                   form=request.form, hoje=hoje().isoformat()), 400

        conexao.execute(
            'UPDATE pecas SET nome = ?, quantidade = ?, preco = ?, fornecedor = ?, '
            'observacao = ?, data = ? WHERE id = ?', dados + (id,))
        conexao.commit()
        conexao.close()

        flash('Peça atualizada com sucesso.', 'sucesso')
        return redirect('/')

    conexao.close()
    form = {
        'nome': peca[1],
        'quantidade': peca[2],
        'preco': '%.2f' % peca[3],
        'fornecedor': peca[4] or '',
        'observacao': peca[5] or '',
        'data': peca[6] or '',
    }
    return render_template('formulario.html', modo='edicao', peca_id=id, erros={},
                           form=form, hoje=hoje().isoformat())


@app.route('/deletar/<int:id>', methods=['POST'])
@login_required
def deletar(id):
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute('DELETE FROM pecas WHERE id = ?', (id,))
    conexao.commit()
    removidos = cursor.rowcount
    conexao.close()
    if removidos:
        flash('Peça excluída.', 'sucesso')
    return redirect('/')


# ------------------------------------------------------------------- erros


@app.errorhandler(400)
def requisicao_invalida(_erro):
    return render_template('erro.html', titulo='Requisição inválida',
                           mensagem='Não foi possível concluir a ação. Sua sessão pode ter expirado: '
                                    'volte à página anterior, recarregue-a e tente novamente.'), 400


@app.errorhandler(403)
def acesso_proibido(_erro):
    return render_template('erro.html', titulo='Acesso restrito',
                           mensagem='Esta área é exclusiva para administradores.'), 403


@app.errorhandler(404)
def nao_encontrado(_erro):
    return render_template('erro.html', titulo='Página não encontrada',
                           mensagem='O endereço acessado ou o item solicitado não existe.'), 404


# Garante que o banco exista (e esteja atualizado) ao iniciar, inclusive via gunicorn
criar_ou_atualizar_banco(app.config['DATABASE'])

if __name__ == '__main__':
    # Para ativar o modo debug apenas no desenvolvimento: FLASK_DEBUG=1 python app.py
    app.run(debug=os.environ.get('FLASK_DEBUG') == '1')
