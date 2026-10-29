# Projeto Estoque

Sistema web de controle de estoque (Python, Flask, SQLite, HTML/CSS/JavaScript) com login pela
API externa do Google e uma área de administração.

## Como executar

    pip install -r requirements.txt
    python app.py

Acesse http://127.0.0.1:5000. O banco `estoque.db` é criado (ou atualizado) automaticamente.

## Configurar o login com o Google (uma vez)

1. Acesse o [Google Cloud Console](https://console.cloud.google.com/) e crie (ou escolha) um projeto.
2. Em **APIs e serviços**, configure a **Tela de permissão OAuth** (tipo "Externo"). Enquanto o app
   estiver em modo de teste, adicione os e-mails que vão entrar como "usuários de teste".
3. Em **Credenciais**, crie um **ID do cliente OAuth** do tipo **Aplicativo da Web** e cadastre em
   **URIs de redirecionamento autorizados** o endereço de retorno do sistema:

        http://127.0.0.1:5000/auth/google/callback

   (se você acessa por `localhost`, cadastre também `http://localhost:5000/auth/google/callback`;
   em produção use o endereço `https://...` do site).
4. Defina as variáveis de ambiente antes de iniciar o app:

   Linux/macOS:

        export GOOGLE_CLIENT_ID="seu-id.apps.googleusercontent.com"
        export GOOGLE_CLIENT_SECRET="seu-segredo"
        export ADMIN_EMAILS="seu.email@gmail.com"

   Windows (PowerShell):

        $env:GOOGLE_CLIENT_ID="seu-id.apps.googleusercontent.com"
        $env:GOOGLE_CLIENT_SECRET="seu-segredo"
        $env:ADMIN_EMAILS="seu.email@gmail.com"

| Variável | Para que serve |
|----------|----------------|
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Credenciais do passo 3 (obrigatórias). **Nunca** coloque o segredo no código ou no GitHub. |
| `ADMIN_EMAILS` | E-mails (separados por vírgula) que sempre entram como administradores. |
| `SECRET_KEY` | Chave que assina a sessão. Se faltar, o sistema gera e guarda uma em `.secret_key`. |
| `OAUTH_REDIRECT_URI` | Só se o endereço de retorno detectado automaticamente não for o cadastrado no Google. |
| `TRUST_PROXY=1` | Use em hospedagens com proxy/HTTPS, para o IP e o endereço de retorno saírem corretos. |
| `FLASK_DEBUG=1` | Modo de desenvolvimento (não use em produção). |

## Quem pode entrar

Ter uma conta Google **não basta**: só entram os e-mails autorizados.
Os administradores liberam e-mails em **Administração → E-mails autorizados**, ou pela linha de comando:

    python autorizar_email.py pessoa@gmail.com          # usuário comum
    python autorizar_email.py pessoa@gmail.com admin    # administrador

### Entrar com e-mail e senha

Além do Google, a pessoa pode entrar com e-mail e senha na própria tela de login.
Quem não tem acesso preenche o pedido em **Solicite ao administrador** (nome, e-mail e uma senha
de pelo menos 8 caracteres). O pedido fica em **Administração → Pedidos de acesso pendentes**:
ao **aprovar** (escolhendo usuário ou administrador), a conta é criada com a senha cadastrada no
pedido; ao **recusar**, nada é liberado e a pessoa pode pedir de novo depois.

## Área do administrador (`/admin`)

- **Quem está acessando agora:** pessoas com atividade nos últimos 5 minutos (nome, e-mail, IP, navegador).
- **E-mails autorizados:** autorizar, desativar/reativar (derruba a sessão aberta) e promover a administrador.
- **Histórico de acessos:** entradas, saídas e tentativas negadas.

O sistema guarda e-mail, nome, endereço IP e navegador de quem acessa. Avise os usuários (LGPD).

## Testes

    python testes.py

Os testes usam um Google simulado e um banco temporário; não precisam de internet nem de credenciais.
