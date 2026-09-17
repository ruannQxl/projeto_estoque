from flask import Flask, render_template, request, redirect
import sqlite3

app = Flask(__name__)

@app.route('/')
def home():
    conexao = sqlite3.connect('estoque.db')
    cursor = conexao.cursor()
    cursor.execute('SELECT * FROM pecas')
    pecas_banco = cursor.fetchall()
    conexao.close()
    return render_template('index.html', pecas=pecas_banco)

@app.route('/cadastrar', methods=['GET', 'POST'])
def cadastrar():
    if request.method == 'POST':
        nome = request.form['nome']
        quantidade = request.form['quantidade']
        preco = request.form['preco']
        cep = request.form['cep']
        rua = request.form['rua']
        bairro = request.form['bairro']
        
        conexao = sqlite3.connect('estoque.db')
        cursor = conexao.cursor()
        cursor.execute('INSERT INTO pecas (nome, quantidade, preco, cep, rua, bairro) VALUES (?, ?, ?, ?, ?, ?)', (nome, quantidade, preco, cep, rua, bairro))
        conexao.commit()
        conexao.close()
        
        return redirect('/')
        
    return render_template('cadastro.html')

@app.route('/deletar/<int:id>', methods=['POST'])
def deletar(id):
    conexao = sqlite3.connect('estoque.db')
    cursor = conexao.cursor()
    cursor.execute('DELETE FROM pecas WHERE id = ?', (id,))
    conexao.commit()
    conexao.close()
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)