import sqlite3

conexao = sqlite3.connect('estoque.db')
cursor = conexao.cursor()

cursor.execute('''
    CREATE TABLE IF NOT EXISTS pecas (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT NOT NULL,
        quantidade INTEGER NOT NULL,
        preco REAL NOT NULL,
        cep TEXT,
        rua TEXT,
        bairro TEXT
    )
''')

conexao.commit()
conexao.close()

print("Banco de dados atualizado com novos campos!")