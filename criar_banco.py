"""
Essa parte é o banco de dados
"""

import sqlite3

conexao = sqlite3.connect('estoque.db')
cursor = conexao.cursor()
"""Aqui vai ficar os campos do cadastro de itens"""
cursor.execute('''
    CREATE TABLE IF NOT EXISTS pecas (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        Nome TEXT NOT NULL,
        quantidade INTEGER NOT NULL,
        preco REAL NOT NULL,
        fornecedor TEXT,
        observacao TEXT,
        cep TEXT,
        rua TEXT,
        bairro TEXT
    )
''')

conexao.commit()
conexao.close()

print("Banco de dados atualizado com novos campos!")