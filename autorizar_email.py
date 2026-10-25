"""Autoriza um e-mail a entrar no sistema (sem precisar abrir a área de administração).

Uso:
    python autorizar_email.py pessoa@gmail.com            # usuário comum
    python autorizar_email.py pessoa@gmail.com admin      # administrador
"""

import re
import sys

from criar_banco import CAMINHO_PADRAO, autorizar_email, criar_ou_atualizar_banco


def main():
    argumentos = sys.argv[1:]
    if not argumentos or len(argumentos) > 2:
        print(__doc__)
        sys.exit(1)

    email = argumentos[0].strip().lower()
    papel = argumentos[1] if len(argumentos) == 2 else 'usuario'
    if not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', email) or papel not in ('admin', 'usuario'):
        print('E-mail inválido ou papel desconhecido (use "admin" ou "usuario").')
        sys.exit(1)

    criar_ou_atualizar_banco(CAMINHO_PADRAO)
    autorizar_email(CAMINHO_PADRAO, email, papel)
    print(f'{email} autorizado como {papel}.')


if __name__ == '__main__':
    main()
