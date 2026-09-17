from flask import Flask, render_template, request, redirect
import sqlite3

app = Flask(__name__)

@app.route('/')
def home():
    conexao = sqlite3.connect('estoque.db')
    cursor = conexao.cursor()
    cursor.execute('SELECT * FROM pecas')
    pecas_banco = cursor.fetchall()
    
    # Calculando métricas profissionais para o Dashboard
    total_tipos = len(pecas_banco)
    total_unidades = sum(p[2] for p in pecas_banco) if pecas_banco else 0
    valor_total_estoque = sum(p[2] * p[3] for p in pecas_banco) if pecas_banco else 0
    
    conexao.close()
    return render_template('index.html', 
                           pecas=pecas_banco, 
                           total_tipos=total_tipos, 
                           total_unidades=total_unidades, 
                           valor_total_estoque=valor_total_estoque)

@app.route('/cadastrar', methods=['GET', 'POST'])
def cadastrar():
    if request.method == 'POST':
        nome = request.form['nome']
        quantidade = int(request.form['quantidade'])
        preco = float(request.form['preco'])
        cep = request.form['cep']
        rua = request.form['rua']
        bairro = request.form['bairro']
        
        conexao = sqlite3.connect('estoque.db')
        cursor = conexao.cursor()
        cursor.execute('INSERT INTO pecas (nome, quantidade, preco, cep, rua, bairro) VALUES (?, ?, ?, ?, ?, ?)', 
                       (nome, quantidade, preco, cep, rua, bairro))
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