from flask import Flask, render_template, request, redirect
import sqlite3

app = Flask(__name__)

@app.route('/')
def home():
    # Conecta no banco e puxa todas as peças cadastradas
    conexao = sqlite3.connect('estoque.db')
    cursor = conexao.cursor()
    cursor.execute('SELECT * FROM pecas')
    pecas_banco = cursor.fetchall()
    conexao.close()
    
    # Envia a lista de peças para o HTML (a tela) usar
    return render_template('index.html', pecas=pecas_banco)

@app.route('/cadastrar', methods=['GET', 'POST'])
def cadastrar():
    if request.method == 'POST':
        nome = request.form['nome']
        quantidade = request.form['quantidade']
        preco = request.form['preco']
        
        conexao = sqlite3.connect('estoque.db')
        cursor = conexao.cursor()
        cursor.execute('INSERT INTO pecas (nome, quantidade, preco) VALUES (?, ?, ?)', (nome, quantidade, preco))
        conexao.commit()
        conexao.close()
        
        return redirect('/')
        
    return render_template('cadastro.html')

if __name__ == '__main__':
    app.run(debug=True)