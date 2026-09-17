import unittest
from app import app

class TesteSistemaEstoque(unittest.TestCase):
    
    # Prepara o ambiente antes de cada teste
    def setUp(self):
        # Cria um "cliente falso" que simula o nosso navegador
        self.cliente_de_teste = app.test_client()

    # O teste em si (tudo que começa com 'test_' o Python reconhece como teste)
    def test_pagina_inicial_online(self):
        # O robô tenta acessar a página inicial ('/')
        resposta = self.cliente_de_teste.get('/')
        
        # Na internet, o código 200 significa "Tudo OK, página carregada".
        # O robô verifica se o sistema respondeu com 200.
        self.assertEqual(resposta.status_code, 200)
        print("\n✅ TESTE PASSOU: A página inicial está online e funcionando perfeitamente!")

if __name__ == '__main__':
    unittest.main()