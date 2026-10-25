from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3

app = Flask(__name__)
app.secret_key = 'sua_chave_secreta'

def conectar_banco():
    return sqlite3.connect('estoque.db')

@app.route('/')
def index():
    conexao = conectar_banco()
    cursor = conexao.cursor()
    cursor.execute('SELECT id, nome, quantidade, preco, data FROM itens')
    itens = cursor.fetchall()
    conexao.close()
    return render_template('index.html', itens=itens)

@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if request.method == 'POST':
        nome = request.form['nome']
        quantidade = request.form['quantidade']
        preco = request.form['preco']
        data = request.form['data']
        
        conexao = conectar_banco()
        cursor = conexao.cursor()
        cursor.execute('INSERT INTO itens (nome, quantidade, preco, data) VALUES (?, ?, ?, ?)',
                       (nome, quantidade, preco, data))
        conexao.commit()
        conexao.close()
        return redirect(url_for('index'))
    return render_template('cadastro.html')

@app.route('/editar/<int:id>', methods=['GET', 'POST'])
def editar(id):
    conexao = conectar_banco()
    cursor = conexao.cursor()
    
    if request.method == 'POST':
        nome = request.form['nome']
        quantidade = request.form['quantidade']
        preco = request.form['preco']
        data = request.form['data']
        
        cursor.execute('''
            UPDATE itens SET nome = ?, quantidade = ?, preco = ?, data = ?
            WHERE id = ?
        ''', (nome, quantidade, preco, data, id))
        conexao.commit()
        conexao.close()
        return redirect(url_for('index'))
    
    cursor.execute('SELECT id, nome, quantidade, preco, data FROM itens WHERE id = ?', (id,))
    item = cursor.fetchone()
    conexao.close()
    return render_template('editar.html', item=item)

@app.route('/login/google')
def login_google():
    # Rota preparada para integração de autenticação externa (Google OAuth)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
