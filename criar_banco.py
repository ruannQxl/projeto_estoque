"""
Criação e atualização do banco de dados (SQLite).

Pode ser executado diretamente (python criar_banco.py) e também é chamado
automaticamente pelo app.py ao iniciar. Se o banco já existir com um esquema
antigo, ele é atualizado sem apagar os itens cadastrados.

Tabelas:
  pecas    - itens do estoque
  contas   - e-mails autorizados a entrar (papel: 'admin' ou 'usuario')
  sessoes  - sessões de login (para saber quem está online agora)
  acessos  - histórico de entradas, saídas e acessos negados
"""

import os
import sqlite3
from datetime import datetime, timezone

CAMINHO_PADRAO = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'estoque.db')

# Colunas que podem faltar em bancos criados antes: nome -> tipo
COLUNAS_OPCIONAIS = {
    'fornecedor': 'TEXT',
    'observacao': 'TEXT',
    'data': 'TEXT',  # data de entrada da peça (AAAA-MM-DD)
}

# Campos que deixaram de existir no sistema
COLUNAS_REMOVIDAS = ('cep', 'rua', 'bairro')


def agora_texto():
    """Data e hora atuais em UTC, no formato guardado no banco."""
    return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')


def criar_ou_atualizar_banco(caminho=CAMINHO_PADRAO):
    conexao = sqlite3.connect(caminho)
    cursor = conexao.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS pecas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            quantidade INTEGER NOT NULL,
            preco REAL NOT NULL,
            fornecedor TEXT,
            observacao TEXT,
            data TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS contas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            nome TEXT,
            papel TEXT NOT NULL DEFAULT 'usuario' CHECK (papel IN ('admin', 'usuario')),
            ativo INTEGER NOT NULL DEFAULT 1,
            criado_em TEXT NOT NULL,
            ultimo_acesso TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessoes (
            sid TEXT PRIMARY KEY,
            email TEXT NOT NULL,
            ip TEXT,
            navegador TEXT,
            inicio TEXT NOT NULL,
            ultima_atividade TEXT NOT NULL,
            encerrada INTEGER NOT NULL DEFAULT 0
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS acessos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            quando TEXT NOT NULL,
            evento TEXT NOT NULL,
            email TEXT,
            nome TEXT,
            ip TEXT,
            navegador TEXT
        )
    ''')

    # A tabela de usuários com senha pertencia ao login local, que foi substituído pelo login com o Google
    cursor.execute('DROP TABLE IF EXISTS usuarios')

    # Migração de bancos antigos
    existentes = {linha[1] for linha in cursor.execute('PRAGMA table_info(pecas)')}
    for coluna, tipo in COLUNAS_OPCIONAIS.items():
        if coluna not in existentes:
            cursor.execute(f'ALTER TABLE pecas ADD COLUMN {coluna} {tipo}')

    for coluna in COLUNAS_REMOVIDAS:
        if coluna in existentes:
            try:
                cursor.execute(f'ALTER TABLE pecas DROP COLUMN {coluna}')
            except sqlite3.OperationalError:
                pass  # SQLite anterior à 3.35: a coluna permanece, mas deixa de ser usada

    conexao.commit()
    conexao.close()


def autorizar_email(caminho, email, papel='usuario', nome=None):
    """Autoriza um e-mail a entrar (ou reativa e atualiza o papel de um já existente)."""
    email = email.strip().lower()
    conexao = sqlite3.connect(caminho)
    conexao.execute(
        'INSERT INTO contas (email, nome, papel, ativo, criado_em) VALUES (?, ?, ?, 1, ?) '
        'ON CONFLICT(email) DO UPDATE SET papel = excluded.papel, ativo = 1, '
        'nome = COALESCE(contas.nome, excluded.nome)',
        (email, nome, papel, agora_texto()))
    conexao.commit()
    conexao.close()


if __name__ == '__main__':
    criar_ou_atualizar_banco()
    print("Banco de dados criado/atualizado com sucesso!")
