import os
import tempfile
import unittest

from app import app
from criar_banco import criar_ou_atualizar_banco


class TesteSistemaEstoque(unittest.TestCase):

    def setUp(self):
        # Usa um banco temporário para não alterar o estoque.db real
        self.arquivo_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        self.arquivo_db.close()
        app.config['DATABASE'] = self.arquivo_db.name
        criar_ou_atualizar_banco(self.arquivo_db.name)
        self.cliente = app.test_client()

    def tearDown(self):
        os.unlink(self.arquivo_db.name)

    def cadastrar(self, **extra):
        dados = dict(nome='Tela iPhone 13', quantidade='5', preco='399.90',
                     fornecedor='Fornecedor X', observacao='Original',
                     cep='01001000', rua='Praça da Sé', bairro='Sé')
        dados.update(extra)
        return self.cliente.post('/cadastrar', data=dados)

    def test_pagina_inicial_online(self):
        self.assertEqual(self.cliente.get('/').status_code, 200)

    def test_pagina_de_cadastro_online(self):
        self.assertEqual(self.cliente.get('/cadastrar').status_code, 200)

    def test_cadastro_valido_aparece_na_lista(self):
        resposta = self.cadastrar()
        self.assertEqual(resposta.status_code, 302)
        html = self.cliente.get('/').get_data(as_text=True)
        self.assertIn('Tela iPhone 13', html)
        self.assertIn('Fornecedor X', html)
        self.assertIn('399.90', html)

    def test_quantidade_negativa_e_rejeitada(self):
        resposta = self.cadastrar(quantidade='-1')
        self.assertEqual(resposta.status_code, 400)
        self.assertNotIn('Tela iPhone 13', self.cliente.get('/').get_data(as_text=True))

    def test_quantidade_invalida_nao_gera_erro_500(self):
        self.assertEqual(self.cadastrar(quantidade='abc').status_code, 400)

    def test_busca_por_nome(self):
        self.cadastrar()
        self.cadastrar(nome='Bateria Samsung')
        html = self.cliente.get('/?busca=bateria').get_data(as_text=True)
        self.assertIn('Bateria Samsung', html)
        self.assertNotIn('Tela iPhone 13', html)

    def test_deletar_peca(self):
        self.cadastrar()
        self.cliente.post('/deletar/1')
        self.assertNotIn('Tela iPhone 13', self.cliente.get('/').get_data(as_text=True))

    def test_migracao_de_banco_antigo(self):
        import sqlite3
        antigo = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        antigo.close()
        con = sqlite3.connect(antigo.name)
        con.execute('CREATE TABLE pecas (id INTEGER PRIMARY KEY AUTOINCREMENT, nome TEXT NOT NULL, '
                    'quantidade INTEGER NOT NULL, preco REAL NOT NULL, cep TEXT, rua TEXT, bairro TEXT)')
        con.execute("INSERT INTO pecas (nome, quantidade, preco) VALUES ('TELA 16E', 20, 399.0)")
        con.commit(); con.close()
        criar_ou_atualizar_banco(antigo.name)
        con = sqlite3.connect(antigo.name)
        colunas = {l[1] for l in con.execute('PRAGMA table_info(pecas)')}
        total = con.execute('SELECT COUNT(*) FROM pecas').fetchone()[0]
        con.close(); os.unlink(antigo.name)
        self.assertTrue({'fornecedor', 'observacao'} <= colunas)
        self.assertEqual(total, 1)  # dados antigos preservados


if __name__ == '__main__':
    unittest.main(verbosity=2)
