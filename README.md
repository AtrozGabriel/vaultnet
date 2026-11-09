# VaultNet HTTP

Aplicação Python para compartilhar arquivos no próprio computador ou numa rede local. Inclui login, autenticação em dois fatores, permissões, antivírus, armazenamento criptografado e registros de atividades.

Esta edição usa **HTTP** e não precisa de Caddy, certificados ou BAT de certificado.

## Abrir no Windows

1. Encerre a versão anterior, se estiver aberta.
2. Extraia o ZIP inteiro e abra a pasta `login_rede_offline_http`.
3. Dê dois cliques em **`INICIAR.bat`** e aguarde a verificação.
4. O terminal pergunta se você deseja criar uma conta de administrador. Digite **`y`** para informar usuário, senha e confirmação, ou **`n`** para abrir o sistema diretamente. A pergunta aparece em todas as inicializações pelo BAT, mesmo quando já existem contas.
5. O navegador abre em **http://127.0.0.1:8080/login**. Entre com sua conta e conclua o 2FA.

Não existe usuário pronto. No primeiro uso, escolha `y` para criar uma conta e conseguir entrar. Se escolher `n` com o banco vazio, a tela de login abre; você pode encerrar o sistema e abrir o BAT novamente para cadastrar. O nome deve ter de 3 a 40 caracteres, usando letras sem acento, números, ponto, hífen ou sublinhado. A senha deve ter de 9 a 128 caracteres. No primeiro login, adicione o QR code ao autenticador, confirme o código e guarde os códigos de recuperação.

Quando já houver administradores, `y` cria uma conta adicional com outro nome. Nomes em uso são recusados. Entradas inválidas e senhas divergentes podem ser corrigidas no próprio terminal. Pelo site, a criação de contas permanece na área do administrador.

O BAT procura Python 3.14 ou 3.12 x64 já instalado, inclusive o ambiente do projeto, o lançador `py` e executáveis no PATH. Confere o pip e cada versão de dependência, reaproveita o que está correto e instala somente o que faltar ou estiver incompatível. As dependências são instaladas a partir dos wheels locais, com hashes obrigatórios e sem acesso à internet.

Se faltar o próprio Python, o BAT tenta instalar Python 3.14.8 x64 com WinGet, para o usuário atual. Somente esse caso exige internet e WinGet disponível. Se não for possível, instale Python 3.14 ou 3.12 de 64 bits pelo [site oficial](https://www.python.org/downloads/windows/) e abra o BAT novamente.

Mantenha a janela aberta enquanto usa o sistema. **Ctrl+C encerra o servidor.** O atalho evita abrir duas instâncias ao mesmo tempo. Se houver erro, a janela mostra a mensagem e permanece aberta.

## Navegar na plataforma

- **Início:** resumo de arquivos e atividades.
- **Meus arquivos / Compartilhados:** documentos disponíveis para sua conta.
- **Enviar arquivo:** selecione o documento, categoria, descrição e quem poderá acessá-lo.
- **Detalhes:** informações do arquivo e download; edição conforme a permissão.
- **Lixeira:** administração de documentos excluídos.
- **Meu perfil / Segurança:** senha, sessões e regras de acesso.
- **Usuários e registros:** administração de contas e acompanhamento das atividades.

Os perfis são atendente, supervisor e administrador. Arquivos privados são acessíveis pelo proprietário e pelos administradores; os de equipe são compartilhados com usuários autenticados.

O limite por arquivo é **10 MB (10.485.760 bytes)**. São aceitos PDF, PNG, JPG/JPEG, TXT, CSV, DOCX, XLSX e PPTX, com validações de conteúdo. A cota padrão é de 1 GB, incluindo documentos na lixeira.

O botão **Copiar** utiliza a área de transferência quando disponível. Em HTTP na LAN, alguns navegadores bloqueiam essa função automática; o campo é selecionado e o botão orienta a copiar manualmente. Use Ctrl+C ou a opção Copiar do dispositivo.

## Antivírus e problemas de upload

No Windows, a aplicação procura o Microsoft Defender. ClamAV também pode ser configurado. O arquivo só é armazenado após uma análise aprovada; antivírus ausente, indisponível, sem permissão ou com resultado inconclusivo bloqueia o envio.

Para testar o scanner, abra o PowerShell na pasta do projeto:

```powershell
.\.venv\Scripts\python.exe manage.py verificar-antivirus --scanner defender
```

O diagnóstico usa um arquivo de texto inofensivo. Se o Defender não permitir a análise, confira suas permissões com o responsável pela máquina ou configure ClamAV. Não eleve toda a aplicação web apenas para resolver o scanner.

Existe uma opção de demonstração somente no próprio computador:

```powershell
.\.venv\Scripts\python.exe manage.py executar --demo-sem-antivirus --scanner nenhum
```

O uso dessa opção deve ser feito com arquivos fictícios. Ela é recusada na LAN, e documentos enviados sem análise ficam bloqueados para download ao voltar ao modo normal.

## Acesso por outra máquina da LAN

O BAT abre apenas no próprio computador. Para liberar uma subrede de laboratório, pare o sistema e execute o comando abaixo, substituindo os endereços pelos da sua rede:

```powershell
.\.venv\Scripts\python.exe manage.py executar --rede-local --subrede 192.168.1.0/24 --host-login 192.168.1.10
```

Nesse exemplo, `192.168.1.10` é o servidor. Os clientes acessam **http://192.168.1.10:8080**. Se usar um nome como `login.interno`, ele precisa resolver para o servidor no DNS ou no arquivo hosts dos clientes.

O responsável pela rede precisa permitir a porta TCP 8080 no firewall da rede privada. Não encaminhe essa porta para a internet. O servidor confere a origem real e o Host recebido; cabeçalhos de proxy enviados pelo cliente não podem alterar esses valores. O acesso local do próprio servidor também permanece disponível.

A rede funciona sem internet depois de preparar Python, dependências, antivírus e autenticador. O servidor e os celulares precisam manter o horário correto.

Se a porta estiver ocupada, encerre a outra instância ou use `--porta 8081`; nesse caso, o endereço também passa a usar 8081.

## Atualizar ou trazer dados da edição anterior

1. Encerre as duas edições e faça um backup consistente da pasta **`dados`** anterior.
2. Extraia a nova edição numa pasta separada.
3. Copie a pasta `dados` para dentro de `login_rede_offline_http`, preservando banco, chaves e documentos.
4. Abra `INICIAR.bat` na nova pasta. Deixe o atalho preparar o ambiente necessário; não copie `.venv` entre pastas.
5. Entre novamente com sua conta. Na primeira inicialização HTTP, as sessões antigas são encerradas; usuários, senhas, autenticadores, recuperação e documentos são preservados.

Não aponte as duas edições simultaneamente para a mesma pasta de dados. Certificados que estejam na subpasta antiga `dados/https` não são utilizados pela edição HTTP e não são importados ou apagados pelo inicializador. O certificado já instalado no Windows também não é removido automaticamente.

Guarde um backup da pasta inteira `dados`. A perda das chaves pode tornar os documentos ou segredos do autenticador irrecuperáveis. Use o endereço HTTP exibido pela nova edição; favoritos antigos podem apontar para outro protocolo ou porta.

## Onde ficam as contas e senhas

Na pasta do projeto no servidor, **`dados/login.sqlite3`** é o banco SQLite. A tabela `usuarios` guarda o nome de usuário, perfil, estado da conta e o hash Argon2id da senha. A senha original não é gravada em texto; a aplicação compara a senha digitada com o hash para validar o login. Atualmente não existe campo de email.

Os segredos do autenticador ficam criptografados no banco, com a chave em `dados/chave_2fa.key`. As contas criadas pelo terminal ou pelo site usam o mesmo banco. O ZIP distribuído não inclui contas, banco nem chaves: esses arquivos são criados durante o uso. Para backup, copie a pasta `dados` inteira com o sistema encerrado, como explicado acima.

## Início manual e Linux

No Windows, após o preparo, o servidor pode ser iniciado manualmente:

```powershell
.\.venv\Scripts\python.exe manage.py executar
```

Para criar uma conta pelo terminal:

```powershell
.\.venv\Scripts\python.exe manage.py criar-usuario --perfil administrador
```

No Linux x64 com Python 3.14:

```bash
python3.14 -m venv .venv
.venv/bin/python -m pip install --no-index --find-links wheels/linux-py314-x64 --only-binary=:all: --require-hashes -r requirements.lock
.venv/bin/python manage.py criar-usuario --perfil administrador
.venv/bin/python manage.py executar
```

Para Python 3.12, use `python3.12` e `wheels/linux-py312-x64`. No Windows, os pacotes equivalentes ficam em `wheels/windows-py312-x64` e `wheels/windows-py314-x64`. O comando manual pede usuário, senha e confirmação quando cria uma conta.

## Segurança e validação

Continuam implementados Argon2id para senhas, 2FA obrigatório, proteção CSRF, cookies HttpOnly e SameSite, limites de tentativa, rotação e expiração de sessões, permissões no servidor, antivírus e criptografia autenticada dos arquivos no disco.

O cookie `vaultnet_http` utiliza HttpOnly e SameSite=Lax, sem o atributo Secure. O servidor não envia HSTS, e a conexão não utiliza criptografia TLS.

Para rodar a suíte:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Foram aprovados **156 testes em Python 3.12 e 156 em Python 3.14**, no Linux x64. Os testes cobrem o mínimo de 9 caracteres no cadastro, na troca e na redefinição de senha; entradas de 8 caracteres são recusadas. A inicialização foi exercitada em terminal interativo real, com cadastro do primeiro administrador, cadastro adicional e abertura sem cadastro usando `n`, preservando contas e chaves. No navegador, foram conferidos login com 2FA, cadastro e troca de senha com 9 caracteres, navegação e layout móvel.

Na validação inicial desta edição, também passaram uploads/downloads de documentos de 32,8 KB, 218 KB, 1 MB, 5 MB e 10 MB, além de uma imagem PNG. Os downloads foram comparados byte a byte. A migração de uma instalação de teste da edição anterior preservou contas, senhas, autenticador e arquivos.

A cópia manual e os links HTTP foram verificados numa origem LAN simulada no navegador, com transporte de teste em loopback. Os testes de upload usaram aprovação simulada do scanner; o Defender real não foi executado neste ambiente.

Os resultados atuais ficam em `docs/validacao.json`. A execução nativa do BAT/WinGet, o Defender real e o acesso entre dois computadores Windows ainda precisam ser confirmados no ambiente do grupo.

## Arquivos principais

| Arquivo ou pasta | Função |
| --- | --- |
| `INICIAR.bat` / `iniciar_windows.py` | Verificação, preparação e abertura automática do HTTP |
| `app.py` | Login, 2FA, sessões, usuários e migração |
| `arquivos.py` | Upload, download, permissões e armazenamento |
| `antivirus.py` | Integração com Defender e ClamAV |
| `servidor.py` | Servidor HTTP direto com Waitress |
| `manage.py` / `terminal.py` | Administração e entrada de credenciais |
| `templates/` / `static/` | Telas, estilo, interações, fontes e ícones |
| `requirements.lock` / `requirements.txt` | Versões e hashes das dependências |
| `wheels/` | Pacotes para instalação offline |
| `tests/` | Testes automatizados |
| `dados/` | Dados privados criados durante o uso |

Os demais documentos Markdown da edição anterior foram guardados num arquivo de apoio separado. Este README reúne as instruções necessárias para esta edição.

A pesquisa anterior às alterações consultou [MDN — cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie), [MDN — área de transferência](https://developer.mozilla.org/en-US/docs/Web/API/Clipboard/writeText), [OWASP — transporte](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html) e [Waitress — configuração](https://docs.pylonsproject.org/projects/waitress/en/stable/arguments.html).
