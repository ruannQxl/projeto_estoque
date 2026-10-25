import sqlite3

def criar_tabela():
    conexao = sqlite3.connect('estoque.db')
    cursor = conexao.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS itens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            quantidade INTEGER NOT NULL,
            preco REAL NOT NULL,
            data TEXT NOT NULL
        )
    ''')
    
    conexao.commit()
    conexao.close()

if __name__ == '__main__':
    criar_tabela()
