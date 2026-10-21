import os
import sqlite3

from flask import Flask, render_template, request, redirect

from criar_banco import CAMINHO_PADRAO, criar_ou_atualizar_banco

app = Flask(__name__)
app.config['DATABASE'] = CAMINHO_PADRAO

COLUNAS = 'id, nome, quantidade, preco, fornecedor, observacao'


def conectar():
    return sqlite3.connect(app.config['DATABASE'])


def validar_formulario(form):
    """Lê e valida os dados do cadastro. Retorna (dados, erro)."""
    nome = form.get('nome', '').strip()
    fornecedor = form.get('fornecedor', '').strip()
    observacao = form.get('observacao', '').strip()
    cep = ''.join(c for c in form.get('cep', '') if c.isdigit())
    rua = form.get('rua', '').strip()
    bairro = form.get('bairro', '').strip()

    if not nome:
        return None, 'Informe o nome da peça.'

    try:
        quantidade = int(form.get('quantidade', ''))
    except ValueError:
        return None, 'A quantidade deve ser um número inteiro.'
    if quantidade < 0:
        return None, 'A quantidade não pode ser negativa.'

    try:
        preco = float(form.get('preco', '').replace(',', '.'))
    except ValueError:
        return None, 'O preço deve ser um número válido.'
    if preco < 0:
        return None, 'O preço não pode ser negativo.'

    return (nome, quantidade, preco, fornecedor, observacao, cep, rua, bairro), None


@app.route('/')
def home():
    # Pega o termo de busca enviado pelo usuário (se houver)
    termo_busca = request.args.get('busca', '').strip()

    conexao = conectar()
    cursor = conexao.cursor()

    if termo_busca:
        # Filtra no banco de dados usando LIKE para buscar partes do nome
        cursor.execute(f'SELECT {COLUNAS} FROM pecas WHERE nome LIKE ?',
                       ('%' + termo_busca + '%',))
    else:
        cursor.execute(f'SELECT {COLUNAS} FROM pecas')

    pecas_banco = cursor.fetchall()
    conexao.close()

    total_tipos = len(pecas_banco)
    total_unidades = sum(p[2] for p in pecas_banco)
    valor_total_estoque = sum(p[2] * p[3] for p in pecas_banco)

    return render_template('index.html',
                           pecas=pecas_banco,
                           total_tipos=total_tipos,
                           total_unidades=total_unidades,
                           valor_total_estoque=valor_total_estoque,
                           termo_busca=termo_busca)


@app.route('/cadastrar', methods=['GET', 'POST'])
def cadastrar():
    if request.method == 'POST':
        dados, erro = validar_formulario(request.form)
        if erro:
            # Reexibe o formulário com a mensagem e os valores digitados
            return render_template('cadastro.html', erro=erro, form=request.form), 400

        conexao = conectar()
        cursor = conexao.cursor()
        cursor.execute(
            'INSERT INTO pecas (nome, quantidade, preco, fornecedor, observacao, cep, rua, bairro) '
            'VALUES (?, ?, ?, ?, ?, ?, ?, ?)', dados)
        conexao.commit()
        conexao.close()

        return redirect('/')

    return render_template('cadastro.html', erro=None, form={})


@app.route('/deletar/<int:id>', methods=['POST'])
def deletar(id):
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute('DELETE FROM pecas WHERE id = ?', (id,))
    conexao.commit()
    conexao.close()
    return redirect('/')


# Garante que o banco exista (e esteja atualizado) ao iniciar, inclusive via gunicorn
criar_ou_atualizar_banco(app.config['DATABASE'])

if __name__ == '__main__':
    # Para ativar o modo debug apenas no desenvolvimento: FLASK_DEBUG=1 python app.py
    app.run(debug=os.environ.get('FLASK_DEBUG') == '1')
