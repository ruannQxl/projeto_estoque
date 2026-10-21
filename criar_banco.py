"""
Criação e atualização do banco de dados (SQLite).

Pode ser executado diretamente (python criar_banco.py) e também é chamado
automaticamente pelo app.py ao iniciar. Se a tabela já existir com o
esquema antigo (sem os campos novos), as colunas que faltam são adicionadas
sem apagar os dados já cadastrados.
"""

import os
import sqlite3

CAMINHO_PADRAO = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'estoque.db')

# Campos do cadastro de itens (além do id): nome da coluna -> definição
COLUNAS_OPCIONAIS = {
    'fornecedor': 'TEXT',
    'observacao': 'TEXT',
    'cep': 'TEXT',
    'rua': 'TEXT',
    'bairro': 'TEXT',
}


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
            cep TEXT,
            rua TEXT,
            bairro TEXT
        )
    ''')

    # Migração: adiciona colunas que não existem em bancos criados antes
    existentes = {linha[1] for linha in cursor.execute('PRAGMA table_info(pecas)')}
    for coluna, tipo in COLUNAS_OPCIONAIS.items():
        if coluna not in existentes:
            cursor.execute(f'ALTER TABLE pecas ADD COLUMN {coluna} {tipo}')

    conexao.commit()
    conexao.close()


if __name__ == '__main__':
    criar_ou_atualizar_banco()
    print("Banco de dados criado/atualizado com sucesso!")
