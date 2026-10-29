import base64
import hashlib
import io
import json
import os
import re
import sqlite3
import tempfile
import unittest
import urllib.error
from datetime import timedelta
from unittest import mock
from urllib.parse import parse_qs, urlparse

from werkzeug.security import check_password_hash, generate_password_hash

import app as modulo_app
import oauth_google
from app import app, hoje
from criar_banco import autorizar_email, criar_ou_atualizar_banco

ADMIN = 'chefe@exemplo.com'


def token_de(cliente, pagina='/login'):
    """Abre uma página pública (que gera o token CSRF na sessão) e devolve o token."""
    cliente.get(pagina)
    with cliente.session_transaction() as sessao:
        return sessao['csrf']


class BaseTeste(unittest.TestCase):
    """Cada teste usa um banco temporário e um Google simulado (nenhuma chamada de rede)."""

    def setUp(self):
        self.arquivo_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        self.arquivo_db.close()
        self.caminho = self.arquivo_db.name
        app.config['DATABASE'] = self.caminho
        criar_ou_atualizar_banco(self.caminho)

        self.ambiente = mock.patch.dict(os.environ, {
            'GOOGLE_CLIENT_ID': 'cliente-teste', 'GOOGLE_CLIENT_SECRET': 'segredo-teste',
            'ADMIN_EMAILS': ADMIN})
        self.ambiente.start()
        self.perfil = {}
        self.google = mock.patch.object(oauth_google, 'obter_perfil_google', side_effect=lambda *a, **k: dict(self.perfil))
        self.google.start()
        self.cliente = app.test_client()

    def tearDown(self):
        self.google.stop()
        self.ambiente.stop()
        os.unlink(self.caminho)

    # --- auxiliares ---
    def entrar(self, email, nome='Fulano', verificado=True, cliente=None, ip='10.0.0.1', agente=None):
        """Percorre o fluxo completo: /auth/google -> (Google simulado) -> /auth/google/callback."""
        cliente = cliente or self.cliente
        env = {'REMOTE_ADDR': ip}
        if agente:
            env['HTTP_USER_AGENT'] = agente
        inicio = cliente.get('/auth/google', environ_overrides=env)
        self.assertEqual(inicio.status_code, 302)
        estado = parse_qs(urlparse(inicio.headers['Location']).query)['state'][0]
        self.perfil = {'email': email, 'name': nome, 'email_verified': verificado}
        return cliente.get('/auth/google/callback?code=codigo-x&state=' + estado, environ_overrides=env)

    def token(self, cliente=None):
        cliente = cliente or self.cliente
        cliente.get('/cadastrar')
        with cliente.session_transaction() as sessao:
            return sessao['csrf']

    def html(self, url, cliente=None):
        return (cliente or self.cliente).get(url).get_data(as_text=True)

    def como_admin(self):
        self.assertEqual(self.entrar(ADMIN, 'Chefe').status_code, 302)

    def como_usuario(self, email='ana@exemplo.com', nome='Ana', cliente=None, **kw):
        autorizar_email(self.caminho, email, 'usuario')
        resposta = self.entrar(email, nome, cliente=cliente, **kw)
        self.assertEqual(resposta.status_code, 302)
        return resposta

    def consultar(self, sql, params=()):
        con = sqlite3.connect(self.caminho)
        linhas = con.execute(sql, params).fetchall()
        con.close()
        return linhas


class TesteOAuth(unittest.TestCase):

    def test_desafio_pkce_confere_com_sha256(self):
        verificador = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'  # exemplo da RFC 7636
        self.assertEqual(oauth_google.desafio_pkce(verificador), 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM')

    def test_url_de_autorizacao(self):
        url = oauth_google.url_de_autorizacao('meu-id', 'http://x/cb', 'estado1', 'verif')
        partes = urlparse(url)
        consulta = parse_qs(partes.query)
        self.assertEqual(partes.netloc, 'accounts.google.com')
        self.assertEqual(consulta['client_id'], ['meu-id'])
        self.assertEqual(consulta['response_type'], ['code'])
        self.assertEqual(consulta['scope'], ['openid email profile'])
        self.assertEqual(consulta['code_challenge_method'], ['S256'])
        self.assertEqual(consulta['state'], ['estado1'])

    def test_troca_de_codigo_e_busca_de_perfil(self):
        chamadas = []

        def falso_urlopen(requisicao, timeout=None):
            chamadas.append(requisicao)
            corpo = {'access_token': 'tok'} if requisicao.full_url == oauth_google.URL_TOKEN \
                else {'email': 'a@b.com', 'email_verified': True, 'name': 'A'}
            return io.BytesIO(json.dumps(corpo).encode())

        with mock.patch('urllib.request.urlopen', falso_urlopen):
            perfil = oauth_google.obter_perfil_google('id', 'seg', 'cod', 'verif', 'http://x/cb')
        self.assertEqual(perfil['email'], 'a@b.com')
        corpo = parse_qs(chamadas[0].data.decode())
        self.assertEqual(corpo['grant_type'], ['authorization_code'])
        self.assertEqual(corpo['code_verifier'], ['verif'])
        self.assertEqual(chamadas[1].headers['Authorization'], 'Bearer tok')

    def test_falha_de_rede_vira_erro_oauth(self):
        with mock.patch('urllib.request.urlopen', side_effect=urllib.error.URLError('sem rede')):
            with self.assertRaises(oauth_google.ErroOAuth):
                oauth_google.obter_perfil_google('id', 'seg', 'cod', 'verif', 'http://x/cb')


class TesteLoginGoogle(BaseTeste):

    def test_paginas_exigem_login(self):
        for url in ('/', '/cadastrar', '/editar/1', '/admin'):
            resposta = self.cliente.get(url)
            self.assertEqual(resposta.status_code, 302, url)
            self.assertIn('/login', resposta.headers['Location'], url)
        self.assertEqual(self.cliente.post('/deletar/1').status_code, 400)  # sem token CSRF

    def test_pagina_de_login_tem_botao_do_google(self):
        html = self.html('/login')
        self.assertIn('Entrar com Google', html)
        self.assertIn('href="/auth/google', html)

    def test_login_sem_configuracao_mostra_aviso(self):
        with mock.patch.dict(os.environ, {'GOOGLE_CLIENT_ID': '', 'GOOGLE_CLIENT_SECRET': ''}):
            html = self.html('/login')
            self.assertIn('ainda não foi configurado', html)
            self.assertNotIn('Entrar com Google', html)
            resposta = self.cliente.get('/auth/google')
            self.assertEqual(resposta.status_code, 302)
            self.assertIn('/login', resposta.headers['Location'])

    def test_redireciona_para_o_google_com_pkce_e_state(self):
        resposta = self.cliente.get('/auth/google')
        self.assertEqual(resposta.status_code, 302)
        partes = urlparse(resposta.headers['Location'])
        consulta = parse_qs(partes.query)
        self.assertEqual(partes.netloc, 'accounts.google.com')
        self.assertEqual(consulta['client_id'], ['cliente-teste'])
        self.assertTrue(consulta['redirect_uri'][0].endswith('/auth/google/callback'))
        with self.cliente.session_transaction() as sessao:
            verificador = sessao['oauth']['verificador']
        self.assertEqual(consulta['code_challenge'][0], oauth_google.desafio_pkce(verificador))

    def test_admin_da_configuracao_entra_e_vira_admin(self):
        self.como_admin()
        self.assertEqual(self.cliente.get('/').status_code, 200)
        self.assertEqual(self.consultar('SELECT papel, nome FROM contas WHERE email=?', (ADMIN,)), [('admin', 'Chefe')])
        me = self.cliente.get('/api/me').get_json()
        self.assertEqual((me['email'], me['papel']), (ADMIN, 'admin'))

    def test_usuario_autorizado_entra(self):
        self.como_usuario()
        html = self.html('/')
        self.assertIn('Ana', html)
        self.assertNotIn('href="/admin"', html)  # usuário comum não vê o link da administração

    def test_email_nao_autorizado_e_negado_e_registrado(self):
        resposta = self.entrar('intruso@exemplo.com', 'Intruso')
        self.assertEqual(resposta.status_code, 302)
        self.assertIn('/login', resposta.headers['Location'])
        self.assertEqual(self.cliente.get('/').status_code, 302)  # continua sem acesso
        self.assertIn('não está autorizado', self.html('/login'))
        self.assertEqual(self.consultar("SELECT evento, email FROM acessos"), [('negado', 'intruso@exemplo.com')])

    def test_email_nao_verificado_e_negado(self):
        autorizar_email(self.caminho, 'ana@exemplo.com')
        self.entrar('ana@exemplo.com', verificado=False)
        self.assertEqual(self.cliente.get('/').status_code, 302)

    def test_conta_desativada_nao_entra(self):
        autorizar_email(self.caminho, 'ana@exemplo.com')
        con = sqlite3.connect(self.caminho); con.execute("UPDATE contas SET ativo=0"); con.commit(); con.close()
        self.entrar('ana@exemplo.com')
        self.assertEqual(self.cliente.get('/').status_code, 302)

    def test_state_incorreto_e_rejeitado(self):
        self.cliente.get('/auth/google')
        self.perfil = {'email': ADMIN, 'name': 'X', 'email_verified': True}
        resposta = self.cliente.get('/auth/google/callback?code=x&state=falso')
        self.assertIn('/login', resposta.headers['Location'])
        self.assertEqual(self.cliente.get('/').status_code, 302)

    def test_callback_sem_passar_pelo_inicio_e_rejeitado(self):
        self.perfil = {'email': ADMIN, 'name': 'X', 'email_verified': True}
        resposta = self.cliente.get('/auth/google/callback?code=x&state=qualquer')
        self.assertIn('/login', resposta.headers['Location'])
        self.assertEqual(self.cliente.get('/').status_code, 302)

    def test_usuario_cancelou_no_google(self):
        self.cliente.get('/auth/google')
        resposta = self.cliente.get('/auth/google/callback?error=access_denied')
        self.assertIn('/login', resposta.headers['Location'])
        self.assertIn('cancelado', self.html('/login'))

    def test_falha_de_comunicacao_com_o_google(self):
        self.google.stop()
        with mock.patch.object(oauth_google, 'obter_perfil_google', side_effect=oauth_google.ErroOAuth('x')):
            inicio = self.cliente.get('/auth/google')
            estado = parse_qs(urlparse(inicio.headers['Location']).query)['state'][0]
            resposta = self.cliente.get('/auth/google/callback?code=x&state=' + estado)
        self.google.start()
        self.assertIn('/login', resposta.headers['Location'])
        self.assertIn('Não foi possível concluir', self.html('/login'))

    def test_destino_apos_login_e_seguro(self):
        autorizar_email(self.caminho, 'ana@exemplo.com')
        for destino, esperado in (('/cadastrar', '/cadastrar'), ('//evil.com', '/'), ('https://evil.com', '/')):
            cliente = app.test_client()
            inicio = cliente.get('/auth/google', query_string={'next': destino})
            estado = parse_qs(urlparse(inicio.headers['Location']).query)['state'][0]
            self.perfil = {'email': 'ana@exemplo.com', 'name': 'Ana', 'email_verified': True}
            resposta = cliente.get('/auth/google/callback?code=x&state=' + estado)
            self.assertEqual(urlparse(resposta.headers['Location']).path, esperado, destino)

    def test_logout_encerra_sessao_e_registra(self):
        self.como_usuario()
        resposta = self.cliente.post('/logout', data={'csrf_token': self.token()})
        self.assertEqual(resposta.status_code, 302)
        self.assertEqual(self.cliente.get('/').status_code, 302)
        self.assertEqual(self.cliente.get('/api/me').status_code, 401)
        eventos = [e[0] for e in self.consultar('SELECT evento FROM acessos ORDER BY id')]
        self.assertEqual(eventos, ['entrada', 'saida'])

    def test_post_sem_token_csrf_e_rejeitado(self):
        self.como_usuario()
        resposta = self.cliente.post('/cadastrar', data=dict(nome='X', quantidade='1', preco='1', data=hoje().isoformat()))
        self.assertEqual(resposta.status_code, 400)

    def test_login_antigo_com_senha_foi_removido(self):
        self.assertEqual(self.cliente.get('/api/login').status_code, 404)
        self.assertIn(self.cliente.post('/api/login', json={'usuario': 'a', 'senha': 'b'}).status_code, (400, 404))

    def test_pagina_login_acessivel(self):
        html = self.html('/login')
        self.assertIn('lang="pt-BR"', html)
        self.assertIn('class="skip-link"', html)
        self.assertEqual(len(re.findall(r'<h1[ >]', html)), 1)
        self.assertIn('<main id="conteudo"', html)


class TesteAdmin(BaseTeste):

    def test_usuario_comum_nao_acessa_admin(self):
        self.como_usuario()
        self.assertEqual(self.cliente.get('/admin').status_code, 403)
        self.assertIn('Acesso restrito', self.html('/admin'))

    def test_admin_ve_quem_esta_online(self):
        self.como_admin()
        outro = app.test_client()
        self.como_usuario('ana@exemplo.com', 'Ana Souza', cliente=outro, ip='192.168.1.50',
                          agente='Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0 Safari/537.36')
        html = self.html('/admin')
        self.assertIn('Ana Souza', html)
        self.assertIn('ana@exemplo.com', html)
        self.assertIn('192.168.1.50', html)
        self.assertIn('Chrome em Windows', html)
        self.assertIn('Chefe', html)

    def test_quem_saiu_deixa_de_aparecer_online(self):
        self.como_admin()
        outro = app.test_client()
        self.como_usuario('ana@exemplo.com', 'Ana Souza', cliente=outro)
        outro.post('/logout', data={'csrf_token': self.token(outro)})
        html = self.html('/admin')
        secao_online = html.split('Quem está acessando agora')[1].split('E-mails autorizados')[0]
        self.assertNotIn('ana@exemplo.com', secao_online)
        self.assertIn('Saiu', html)  # mas aparece no histórico

    def test_sessao_inativa_nao_aparece_como_online(self):
        self.como_admin()
        outro = app.test_client()
        self.como_usuario('ana@exemplo.com', 'Ana Souza', cliente=outro)
        antigo = (modulo_app.datetime.now(modulo_app.timezone.utc) - timedelta(minutes=30)).strftime('%Y-%m-%d %H:%M:%S')
        con = sqlite3.connect(self.caminho)
        con.execute('UPDATE sessoes SET ultima_atividade=? WHERE email=?', (antigo, 'ana@exemplo.com'))
        con.commit(); con.close()
        secao_online = self.html('/admin').split('Quem está acessando agora')[1].split('E-mails autorizados')[0]
        self.assertNotIn('ana@exemplo.com', secao_online)

    def test_historico_mostra_acesso_negado(self):
        self.entrar('intruso@exemplo.com', 'Intruso', ip='203.0.113.9')
        self.como_admin()
        html = self.html('/admin')
        self.assertIn('Acesso negado', html)
        self.assertIn('intruso@exemplo.com', html)
        self.assertIn('203.0.113.9', html)

    def test_admin_autoriza_novo_email(self):
        self.como_admin()
        resposta = self.cliente.post('/admin/usuarios', data={'email': 'Nova@Exemplo.com', 'papel': 'usuario',
                                                               'csrf_token': self.token()})
        self.assertEqual(resposta.status_code, 302)
        self.assertEqual(self.consultar("SELECT email, papel, ativo FROM contas WHERE email='nova@exemplo.com'"),
                         [('nova@exemplo.com', 'usuario', 1)])
        outro = app.test_client()
        self.assertEqual(self.entrar('nova@exemplo.com', 'Nova', cliente=outro).status_code, 302)
        self.assertEqual(outro.get('/').status_code, 200)

    def test_email_invalido_e_rejeitado(self):
        self.como_admin()
        self.cliente.post('/admin/usuarios', data={'email': 'isto-nao-e-email', 'papel': 'usuario', 'csrf_token': self.token()})
        self.assertEqual(self.consultar("SELECT COUNT(*) FROM contas"), [(1,)])  # só o admin da configuração
        self.assertIn('e-mail válido', self.html('/admin'))

    def test_desativar_derruba_sessao_aberta(self):
        self.como_admin()
        outro = app.test_client()
        self.como_usuario('ana@exemplo.com', 'Ana', cliente=outro)
        self.assertEqual(outro.get('/').status_code, 200)
        id_ana = self.consultar("SELECT id FROM contas WHERE email='ana@exemplo.com'")[0][0]
        self.cliente.post('/admin/usuarios/%d/ativo' % id_ana, data={'csrf_token': self.token()})
        self.assertEqual(outro.get('/').status_code, 302)  # foi desconectada
        self.entrar('ana@exemplo.com', cliente=app.test_client())
        # reativar permite entrar de novo
        self.cliente.post('/admin/usuarios/%d/ativo' % id_ana, data={'csrf_token': self.token()})
        novo = app.test_client()
        self.entrar('ana@exemplo.com', cliente=novo)
        self.assertEqual(novo.get('/').status_code, 200)

    def test_alternar_papel(self):
        self.como_admin()
        autorizar_email(self.caminho, 'ana@exemplo.com')
        id_ana = self.consultar("SELECT id FROM contas WHERE email='ana@exemplo.com'")[0][0]
        self.cliente.post('/admin/usuarios/%d/papel' % id_ana, data={'csrf_token': self.token()})
        self.assertEqual(self.consultar("SELECT papel FROM contas WHERE id=?", (id_ana,)), [('admin',)])

    def test_admin_nao_altera_a_propria_conta_nem_admin_da_configuracao(self):
        self.como_admin()
        id_admin = self.consultar("SELECT id FROM contas WHERE email=?", (ADMIN,))[0][0]
        self.cliente.post('/admin/usuarios/%d/ativo' % id_admin, data={'csrf_token': self.token()})
        self.cliente.post('/admin/usuarios/%d/papel' % id_admin, data={'csrf_token': self.token()})
        self.assertEqual(self.consultar("SELECT papel, ativo FROM contas WHERE id=?", (id_admin,)), [('admin', 1)])
        self.assertIn('própria conta', self.html('/admin'))

    def test_acoes_de_admin_exigem_admin_e_csrf(self):
        autorizar_email(self.caminho, 'ana@exemplo.com')
        id_ana = self.consultar("SELECT id FROM contas WHERE email='ana@exemplo.com'")[0][0]
        self.como_usuario('beto@exemplo.com', 'Beto')
        # usuário comum, com token válido: proibido
        self.assertEqual(self.cliente.post('/admin/usuarios/%d/ativo' % id_ana, data={'csrf_token': self.token()}).status_code, 403)
        self.assertEqual(self.cliente.post('/admin/usuarios', data={'email': 'x@y.com', 'csrf_token': self.token()}).status_code, 403)
        self.assertEqual(self.consultar("SELECT ativo FROM contas WHERE id=?", (id_ana,)), [(1,)])
        # admin sem token: recusado
        self.cliente.post('/logout', data={'csrf_token': self.token()})
        self.como_admin()
        self.assertEqual(self.cliente.post('/admin/usuarios/%d/ativo' % id_ana).status_code, 400)

    def test_conta_inexistente_retorna_404(self):
        self.como_admin()
        self.assertEqual(self.cliente.post('/admin/usuarios/999/ativo', data={'csrf_token': self.token()}).status_code, 404)

    def test_acessibilidade_da_area_admin(self):
        self.como_admin()
        html = self.html('/admin')
        self.assertEqual(len(re.findall(r'<h1[ >]', html)), 1)
        # 4 tabelas: pessoas online, pedidos pendentes, e-mails autorizados e histórico
        self.assertEqual(len(re.findall(r'<caption', html)), 4)
        self.assertIn('scope="col"', html)
        self.assertIn('for="novo-email"', html)
        self.assertIn('for="novo-papel"', html)
        self.assertIn('aria-current="page"', html)
        self.assertIn('class="skip-link"', html)
        self.assertEqual(html.count('role="region"'), 4)


class TesteEstoque(BaseTeste):

    def setUp(self):
        super().setUp()
        self.como_usuario()

    def cadastrar(self, **extra):
        dados = dict(nome='Tela iPhone 13', quantidade='5', preco='399.90',
                     fornecedor='Fornecedor X', observacao='Original', data=hoje().isoformat())
        dados.update(extra)
        dados['csrf_token'] = self.token()
        return self.cliente.post('/cadastrar', data=dados)

    def test_pagina_inicial_e_formulario_online(self):
        self.assertEqual(self.cliente.get('/').status_code, 200)
        self.assertEqual(self.cliente.get('/cadastrar').status_code, 200)

    def test_cadastro_valido_aparece_na_lista_com_data(self):
        self.assertEqual(self.cadastrar(data='2026-03-05').status_code, 302)
        html = self.html('/')
        self.assertIn('Tela iPhone 13', html)
        self.assertIn('05/03/2026', html)
        self.assertIn('datetime="2026-03-05"', html)
        self.assertIn('Peça cadastrada com sucesso.', html)

    def test_data_e_obrigatoria_valida_e_nao_futura(self):
        self.assertEqual(self.cadastrar(data='').status_code, 400)
        self.assertEqual(self.cadastrar(data='31/02/2026').status_code, 400)
        self.assertEqual(self.cadastrar(data=(hoje() + timedelta(days=1)).isoformat()).status_code, 400)

    def test_campos_de_endereco_foram_removidos(self):
        html = self.html('/cadastrar')
        for campo in ('cep', 'rua', 'bairro'):
            self.assertNotIn('id="%s"' % campo, html)
        self.assertNotIn('viacep', html.lower())

    def test_obrigatorios_e_opcionais(self):
        html = self.html('/cadastrar')
        for campo in ('nome', 'quantidade', 'preco', 'data'):
            self.assertIn('required', re.search(r'<input[^>]*\sid="%s"[^>]*>' % campo, html, re.S).group(0), campo)
        for campo in ('fornecedor', 'observacao'):
            self.assertNotIn('required', re.search(r'<input[^>]*\sid="%s"[^>]*>' % campo, html, re.S).group(0), campo)
        self.assertEqual(self.cadastrar(fornecedor='', observacao='').status_code, 302)

    def test_quantidade_negativa_ou_invalida(self):
        self.assertEqual(self.cadastrar(quantidade='-1').status_code, 400)
        self.assertEqual(self.cadastrar(quantidade='abc').status_code, 400)

    def test_busca_por_nome(self):
        self.cadastrar()
        self.cadastrar(nome='Bateria Samsung')
        html = self.html('/?busca=bateria')
        self.assertIn('Bateria Samsung', html)
        self.assertNotIn('Tela iPhone 13', html)

    def test_deletar_peca(self):
        self.cadastrar()
        self.cliente.post('/deletar/1', data={'csrf_token': self.token()})
        self.assertNotIn('Tela iPhone 13', self.html('/'))

    def test_editar_mostra_formulario_preenchido(self):
        self.cadastrar(data='2026-03-05')
        html = self.html('/editar/1')
        self.assertIn('Editar Componente', html)
        self.assertIn('value="Tela iPhone 13"', html)
        self.assertIn('value="2026-03-05"', html)
        self.assertIn('action="/editar/1"', html)

    def test_editar_salva_alteracoes(self):
        self.cadastrar()
        resposta = self.cliente.post('/editar/1', data=dict(
            nome='Tela iPhone 14', quantidade='9', preco='450,00', fornecedor='', observacao='Trocado',
            data='2026-04-10', csrf_token=self.token()))
        self.assertEqual(resposta.status_code, 302)
        html = self.html('/')
        self.assertIn('Tela iPhone 14', html)
        self.assertNotIn('Tela iPhone 13', html)
        self.assertIn('10/04/2026', html)
        self.assertEqual(self.consultar('SELECT COUNT(*) FROM pecas'), [(1,)])

    def test_editar_com_erro_nao_altera(self):
        self.cadastrar()
        resposta = self.cliente.post('/editar/1', data=dict(
            nome='', quantidade='9', preco='1', data=hoje().isoformat(), csrf_token=self.token()))
        self.assertEqual(resposta.status_code, 400)
        self.assertIn('role="alert"', resposta.get_data(as_text=True))
        self.assertIn('Tela iPhone 13', self.html('/'))

    def test_editar_item_inexistente_retorna_404(self):
        self.assertEqual(self.cliente.get('/editar/999').status_code, 404)

    def test_acessibilidade_lista(self):
        self.cadastrar()
        html = self.html('/')
        self.assertEqual(len(re.findall(r'<h1[ >]', html)), 1)
        self.assertIn('<caption', html)
        self.assertIn('Editar<span class="sr-only"> Tela iPhone 13</span>', html)
        self.assertIn('Excluir<span class="sr-only"> Tela iPhone 13</span>', html)
        self.assertIn('role="status"', html)

    def test_acessibilidade_formulario_com_erro(self):
        html = self.cadastrar(quantidade='-1').get_data(as_text=True)
        self.assertIn('role="alert"', html)
        self.assertIn('aria-invalid="true"', html)
        self.assertIn('aria-describedby="erro-quantidade"', html)
        for id_ in re.findall(r'<input(?![^>]*type="hidden")[^>]*\sid="([^"]+)"', html):
            self.assertIn('for="%s"' % id_, html, id_)

    def test_nome_com_aspas_nao_quebra_confirmacao_de_exclusao(self):
        self.cadastrar(nome='Tela d\'água "Plus"')
        atributo = re.search(r"onsubmit='([^']*)'", self.html('/'))
        self.assertIsNotNone(atributo)
        self.assertNotIn('"Plus"', atributo.group(1))

    def test_pagina_404_amigavel(self):
        resposta = self.cliente.get('/nao-existe')
        self.assertEqual(resposta.status_code, 404)
        self.assertIn('Página não encontrada', resposta.get_data(as_text=True))

    def test_preco_nan_ou_infinito_e_rejeitado(self):
        self.assertEqual(self.cadastrar(preco='nan').status_code, 400)
        self.assertEqual(self.cadastrar(preco='inf').status_code, 400)
        self.assertEqual(self.consultar('SELECT COUNT(*) FROM pecas'), [(0,)])

    def test_paginas_internas_nao_vao_para_cache(self):
        self.assertEqual(self.cliente.get('/').headers.get('Cache-Control'), 'no-store')


class TesteBanco(unittest.TestCase):

    def test_migracao_de_banco_antigo(self):
        antigo = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        antigo.close()
        con = sqlite3.connect(antigo.name)
        con.execute('CREATE TABLE pecas (id INTEGER PRIMARY KEY AUTOINCREMENT, nome TEXT NOT NULL, '
                    'quantidade INTEGER NOT NULL, preco REAL NOT NULL, cep TEXT, rua TEXT, bairro TEXT)')
        con.execute('CREATE TABLE usuarios (id INTEGER PRIMARY KEY, usuario TEXT, senha_hash TEXT)')
        con.execute("INSERT INTO pecas (nome, quantidade, preco, cep) VALUES ('TELA 16E', 20, 399.0, '01001000')")
        con.commit(); con.close()

        criar_ou_atualizar_banco(antigo.name)

        con = sqlite3.connect(antigo.name)
        colunas = {l[1] for l in con.execute('PRAGMA table_info(pecas)')}
        total = con.execute('SELECT COUNT(*) FROM pecas').fetchone()[0]
        tabelas = {l[0] for l in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        con.close(); os.unlink(antigo.name)

        self.assertTrue({'fornecedor', 'observacao', 'data'} <= colunas)
        self.assertFalse({'cep', 'rua', 'bairro'} & colunas)
        self.assertTrue({'contas', 'sessoes', 'acessos'} <= tabelas)
        self.assertNotIn('usuarios', tabelas)  # login por senha foi substituído pelo Google
        self.assertEqual(total, 1)


class TesteMigracaoSenha(unittest.TestCase):

    def test_banco_antigo_ganha_senha_hash_em_contas_e_pedidos(self):
        antigo = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        antigo.close()
        con = sqlite3.connect(antigo.name)
        con.execute("""CREATE TABLE contas (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL UNIQUE,
                    nome TEXT, papel TEXT NOT NULL DEFAULT 'usuario', ativo INTEGER NOT NULL DEFAULT 1,
                    criado_em TEXT NOT NULL, ultimo_acesso TEXT)""")
        con.execute("""CREATE TABLE solicitacoes_acesso (id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL UNIQUE, nome TEXT NOT NULL, criado_em TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pendente')""")
        con.execute("INSERT INTO contas (email, nome, criado_em) VALUES ('ana@exemplo.com', 'Ana', '2026-01-01 00:00:00')")
        con.commit(); con.close()

        criar_ou_atualizar_banco(antigo.name)

        con = sqlite3.connect(antigo.name)
        colunas_contas = {l[1] for l in con.execute('PRAGMA table_info(contas)')}
        colunas_pedidos = {l[1] for l in con.execute('PRAGMA table_info(solicitacoes_acesso)')}
        preservado = con.execute('SELECT email, nome FROM contas').fetchall()
        con.close(); os.unlink(antigo.name)

        self.assertIn('senha_hash', colunas_contas)
        self.assertIn('senha_hash', colunas_pedidos)
        self.assertEqual(preservado, [('ana@exemplo.com', 'Ana')])  # dados existentes preservados


class TesteItemSemData(BaseTeste):

    def test_item_antigo_sem_data_aparece_como_nao_informada(self):
        con = sqlite3.connect(self.caminho)
        con.execute("INSERT INTO pecas (nome, quantidade, preco) VALUES ('Antiga', 1, 1.0)")
        con.commit(); con.close()
        self.como_usuario()
        self.assertIn('Não informada', self.html('/'))

class TesteLoginSenha(BaseTeste):
    """Entrada com e-mail e senha, independente do login com o Google."""

    def criar_conta_com_senha(self, email, senha='senha-forte-1', papel='usuario', ativo=1):
        autorizar_email(self.caminho, email, papel)
        con = sqlite3.connect(self.caminho)
        con.execute('UPDATE contas SET senha_hash = ?, ativo = ? WHERE email = ?',
                    (generate_password_hash(senha), ativo, email))
        con.commit(); con.close()

    def entrar_com_senha(self, email, senha, cliente=None, proximo=''):
        cliente = cliente or self.cliente
        token = token_de(cliente)
        return cliente.post('/login', data={'email': email, 'senha': senha,
                                            'csrf_token': token, 'next': proximo})

    def test_entra_com_email_e_senha(self):
        self.criar_conta_com_senha('ana@exemplo.com')
        resposta = self.entrar_com_senha('ana@exemplo.com', 'senha-forte-1')
        self.assertEqual(resposta.status_code, 302)
        self.assertEqual(urlparse(resposta.headers['Location']).path, '/')
        self.assertEqual(self.cliente.get('/').status_code, 200)
        me = self.cliente.get('/api/me').get_json()
        self.assertEqual((me['email'], me['papel']), ('ana@exemplo.com', 'usuario'))
        self.assertEqual(self.consultar('SELECT evento FROM acessos'), [('entrada',)])

    def test_senha_errada_nao_entra_e_fica_no_historico(self):
        self.criar_conta_com_senha('ana@exemplo.com')
        resposta = self.entrar_com_senha('ana@exemplo.com', 'errada')
        self.assertEqual(resposta.status_code, 200)
        self.assertIn('E-mail ou senha inválidos', resposta.get_data(as_text=True))
        self.assertEqual(self.cliente.get('/').status_code, 302)
        self.assertEqual(self.consultar('SELECT evento, email FROM acessos'), [('negado', 'ana@exemplo.com')])

    def test_email_desconhecido_recebe_a_mesma_mensagem_sem_registro(self):
        resposta = self.entrar_com_senha('ninguem@exemplo.com', 'qualquer')
        self.assertIn('E-mail ou senha inválidos', resposta.get_data(as_text=True))
        self.assertEqual(self.consultar('SELECT COUNT(*) FROM acessos'), [(0,)])

    def test_conta_inativa_nao_entra_com_senha(self):
        self.criar_conta_com_senha('ana@exemplo.com', ativo=0)
        self.entrar_com_senha('ana@exemplo.com', 'senha-forte-1')
        self.assertEqual(self.cliente.get('/').status_code, 302)

    def test_conta_sem_senha_so_entra_pelo_google(self):
        autorizar_email(self.caminho, 'ana@exemplo.com')  # autorizada, mas sem senha cadastrada
        resposta = self.entrar_com_senha('ana@exemplo.com', '')
        self.assertIn('E-mail ou senha inválidos', resposta.get_data(as_text=True))

    def test_destino_apos_login_com_senha_e_seguro(self):
        self.criar_conta_com_senha('ana@exemplo.com')
        for destino, esperado in (('/cadastrar', '/cadastrar'), ('https://evil.com', '/')):
            cliente = app.test_client()
            resposta = self.entrar_com_senha('ana@exemplo.com', 'senha-forte-1', cliente=cliente, proximo=destino)
            self.assertEqual(urlparse(resposta.headers['Location']).path, esperado, destino)
            cliente.post('/logout', data={'csrf_token': self.token(cliente)})

    def test_post_de_login_sem_token_csrf_e_rejeitado(self):
        self.criar_conta_com_senha('ana@exemplo.com')
        resposta = self.cliente.post('/login', data={'email': 'ana@exemplo.com', 'senha': 'senha-forte-1'})
        self.assertEqual(resposta.status_code, 400)

    def test_logout_depois_de_entrar_com_senha(self):
        self.criar_conta_com_senha('ana@exemplo.com')
        self.entrar_com_senha('ana@exemplo.com', 'senha-forte-1')
        self.cliente.post('/logout', data={'csrf_token': self.token()})
        self.assertEqual(self.cliente.get('/').status_code, 302)
        self.assertEqual([e[0] for e in self.consultar('SELECT evento FROM acessos ORDER BY id')],
                         ['entrada', 'saida'])

    def test_administrador_com_senha_acessa_a_administracao(self):
        self.criar_conta_com_senha('chefe2@exemplo.com', papel='admin')
        self.entrar_com_senha('chefe2@exemplo.com', 'senha-forte-1')
        self.assertEqual(self.cliente.get('/admin').status_code, 200)

    def test_funciona_mesmo_sem_google_configurado(self):
        self.criar_conta_com_senha('ana@exemplo.com')
        with mock.patch.dict(os.environ, {'GOOGLE_CLIENT_ID': '', 'GOOGLE_CLIENT_SECRET': ''}):
            self.assertEqual(self.entrar_com_senha('ana@exemplo.com', 'senha-forte-1').status_code, 302)

    def test_pagina_de_login_tem_formulario_e_link_para_pedido(self):
        html = self.html('/login')
        self.assertIn('action="/login"', html)
        self.assertIn('name="senha"', html)
        self.assertIn('href="/solicitar-acesso"', html)
        self.assertEqual(len(re.findall(r'<h1[ >]', html)), 1)


class TesteSolicitacaoAcesso(BaseTeste):
    """Quem não tem conta pede acesso; o administrador aprova ou recusa."""

    def pedir(self, cliente=None, **campos):
        cliente = cliente or app.test_client()
        dados = dict(nome='Ana Souza', email='ana@exemplo.com',
                     senha='senha-forte-1', confirmar_senha='senha-forte-1')
        dados.update(campos)
        dados['csrf_token'] = token_de(cliente, '/solicitar-acesso')
        return cliente.post('/solicitar-acesso', data=dados)

    def id_do_pedido(self):
        return self.consultar('SELECT id FROM solicitacoes_acesso')[0][0]

    def test_pedido_valido_fica_pendente_e_nao_guarda_senha_em_texto(self):
        resposta = self.pedir()
        self.assertIn('Pedido enviado com sucesso', resposta.get_data(as_text=True))
        linhas = self.consultar('SELECT email, nome, status, senha_hash FROM solicitacoes_acesso')
        self.assertEqual(len(linhas), 1)
        email, nome, status, senha_hash = linhas[0]
        self.assertEqual((email, nome, status), ('ana@exemplo.com', 'Ana Souza', 'pendente'))
        self.assertNotIn('senha-forte-1', senha_hash)
        self.assertTrue(check_password_hash(senha_hash, 'senha-forte-1'))

    def test_pedido_nao_cria_conta_nem_libera_acesso(self):
        self.pedir()
        self.assertEqual(self.consultar('SELECT COUNT(*) FROM contas'), [(0,)])
        self.assertEqual(self.cliente.get('/').status_code, 302)

    def test_senha_curta_ou_confirmacao_diferente_sao_rejeitadas(self):
        self.assertIn('pelo menos 8', self.pedir(senha='curta', confirmar_senha='curta').get_data(as_text=True))
        self.assertIn('não confere', self.pedir(confirmar_senha='outra-senha-1').get_data(as_text=True))
        self.assertEqual(self.consultar('SELECT COUNT(*) FROM solicitacoes_acesso'), [(0,)])

    def test_email_invalido_ou_sem_nome_e_rejeitado(self):
        self.assertIn('e-mail válido', self.pedir(email='isso-nao').get_data(as_text=True))
        self.assertIn('Informe o seu nome', self.pedir(nome=' ').get_data(as_text=True))

    def test_email_que_ja_tem_conta_nao_gera_pedido(self):
        autorizar_email(self.caminho, 'ana@exemplo.com')
        self.assertIn('já possui cadastro', self.pedir().get_data(as_text=True))
        self.assertEqual(self.consultar('SELECT COUNT(*) FROM solicitacoes_acesso'), [(0,)])

    def test_pedido_repetido_enquanto_pendente_nao_duplica(self):
        self.pedir()
        self.assertIn('pedido pendente', self.pedir().get_data(as_text=True))
        self.assertEqual(self.consultar('SELECT COUNT(*) FROM solicitacoes_acesso'), [(1,)])

    def test_admin_aprova_e_a_pessoa_entra_com_a_senha_escolhida(self):
        self.pedir()
        self.como_admin()
        html = self.html('/admin')
        self.assertIn('Pedidos de acesso pendentes', html)
        self.assertIn('ana@exemplo.com', html)

        resposta = self.cliente.post('/admin/solicitacoes/%d/aprovar' % self.id_do_pedido(),
                                     data={'papel': 'usuario', 'csrf_token': self.token()})
        self.assertEqual(resposta.status_code, 302)
        self.assertEqual(self.consultar("SELECT papel, ativo FROM contas WHERE email='ana@exemplo.com'"),
                         [('usuario', 1)])
        self.assertEqual(self.consultar('SELECT status, senha_hash FROM solicitacoes_acesso'), [('aprovada', None)])

        outro = app.test_client()
        resposta = outro.post('/login', data={'email': 'ana@exemplo.com', 'senha': 'senha-forte-1',
                                              'csrf_token': token_de(outro)})
        self.assertEqual(resposta.status_code, 302)
        self.assertEqual(outro.get('/').status_code, 200)

    def test_admin_recusa_e_a_pessoa_nao_entra(self):
        self.pedir()
        self.como_admin()
        self.cliente.post('/admin/solicitacoes/%d/recusar' % self.id_do_pedido(),
                          data={'csrf_token': self.token()})
        self.assertEqual(self.consultar('SELECT status FROM solicitacoes_acesso'), [('recusada',)])

        outro = app.test_client()
        resposta = outro.post('/login', data={'email': 'ana@exemplo.com', 'senha': 'senha-forte-1',
                                              'csrf_token': token_de(outro)})
        self.assertIn('E-mail ou senha inválidos', resposta.get_data(as_text=True))

        # Pedido recusado pode ser refeito e volta a ficar pendente
        self.assertIn('Pedido enviado com sucesso', self.pedir().get_data(as_text=True))
        self.assertEqual(self.consultar('SELECT status FROM solicitacoes_acesso'), [('pendente',)])

    def test_somente_administrador_aprova_pedidos(self):
        self.pedir()
        id_pedido = self.id_do_pedido()
        self.como_usuario('beto@exemplo.com', 'Beto')
        resposta = self.cliente.post('/admin/solicitacoes/%d/aprovar' % id_pedido,
                                     data={'papel': 'admin', 'csrf_token': self.token()})
        self.assertEqual(resposta.status_code, 403)
        self.assertEqual(self.consultar('SELECT status FROM solicitacoes_acesso'), [('pendente',)])

    def test_aprovar_pedido_inexistente_avisa(self):
        self.como_admin()
        resposta = self.cliente.post('/admin/solicitacoes/999/aprovar',
                                     data={'papel': 'usuario', 'csrf_token': self.token()})
        self.assertEqual(resposta.status_code, 302)
        self.assertIn('não existe mais', self.html('/admin'))

    def test_pagina_de_pedido_tem_titulo_unico_e_campos_de_senha(self):
        html = self.html('/solicitar-acesso')
        self.assertEqual(len(re.findall(r'<h1[ >]', html)), 1)
        self.assertIn('name="senha"', html)
        self.assertIn('name="confirmar_senha"', html)
        self.assertEqual(html.count('<html'), 1)  # sem HTML aninhado



if __name__ == '__main__':
    unittest.main(verbosity=2)
