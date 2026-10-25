"""
Login com a API externa do Google (OAuth 2.0 / OpenID Connect, fluxo "authorization code" com PKCE).

Usa apenas a biblioteca padrão do Python (urllib), sem dependências extras.
Passo a passo:
  1. url_de_autorizacao()      -> endereço do Google para onde o usuário é enviado;
  2. o Google devolve o usuário ao site com um "code";
  3. obter_perfil_google()     -> troca o code por um token (servidor a servidor, via HTTPS)
                                  e busca o perfil (e-mail e nome) da pessoa.
"""

import base64
import hashlib
import json
import secrets
import urllib.error
import urllib.parse
import urllib.request

URL_AUTORIZACAO = 'https://accounts.google.com/o/oauth2/v2/auth'
URL_TOKEN = 'https://oauth2.googleapis.com/token'
URL_PERFIL = 'https://openidconnect.googleapis.com/v1/userinfo'
TEMPO_LIMITE = 10  # segundos


class ErroOAuth(Exception):
    """Falha na comunicação com o Google ou resposta inesperada."""


def gerar_verificador():
    """Segredo aleatório do PKCE (guardado na sessão até o retorno do Google)."""
    return secrets.token_urlsafe(64)


def desafio_pkce(verificador):
    """Versão 'embaralhada' (SHA-256) do verificador, enviada ao Google na ida."""
    resumo = hashlib.sha256(verificador.encode('ascii')).digest()
    return base64.urlsafe_b64encode(resumo).rstrip(b'=').decode('ascii')


def url_de_autorizacao(client_id, redirect_uri, state, verificador):
    parametros = {
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': 'openid email profile',
        'state': state,
        'code_challenge': desafio_pkce(verificador),
        'code_challenge_method': 'S256',
        'prompt': 'select_account',
    }
    return URL_AUTORIZACAO + '?' + urllib.parse.urlencode(parametros)


def _chamar(requisicao):
    try:
        with urllib.request.urlopen(requisicao, timeout=TEMPO_LIMITE) as resposta:
            return json.loads(resposta.read().decode('utf-8'))
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as erro:
        raise ErroOAuth(str(erro)) from erro


def obter_perfil_google(client_id, client_secret, codigo, verificador, redirect_uri):
    """Troca o código por um token e devolve o perfil: {'email', 'email_verified', 'name', ...}."""
    corpo = urllib.parse.urlencode({
        'code': codigo,
        'client_id': client_id,
        'client_secret': client_secret,
        'redirect_uri': redirect_uri,
        'grant_type': 'authorization_code',
        'code_verifier': verificador,
    }).encode('ascii')
    pedido_token = urllib.request.Request(
        URL_TOKEN, data=corpo, method='POST',
        headers={'Content-Type': 'application/x-www-form-urlencoded'})
    token = _chamar(pedido_token).get('access_token')
    if not token:
        raise ErroOAuth('O Google não devolveu o token de acesso.')

    pedido_perfil = urllib.request.Request(URL_PERFIL, headers={'Authorization': 'Bearer ' + token})
    perfil = _chamar(pedido_perfil)
    if not isinstance(perfil, dict):
        raise ErroOAuth('Resposta de perfil inesperada.')
    return perfil
