import sqlite3

# Cria o arquivo do banco de dados (ou conecta se já existir)
conexao = sqlite3.connect('estoque.db')
cursor = conexao.cursor()

# Cria uma "tabela" para guardar as peças da loja
cursor.execute('''
    CREATE TABLE IF NOT EXISTS pecas (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT NOT NULL,
        quantidade INTEGER NOT NULL,
        preco REAL NOT NULL
    )
''')

# Salva e fecha
conexao.commit()
conexao.close()

print("Banco de dados 'estoque.db' criado com sucesso!")