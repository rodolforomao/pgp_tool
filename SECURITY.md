# Segurança — PGP Desk

## Arquitetura

```text
GUI (Tkinter)
    │
    ▼
GpgService (python-gnupg + subprocess estruturado)
    │
    ▼
GnuPG / gpg-agent
    │
    ▼
~/.gnupg/   ← keyring operacional
```

A aplicação **não** implementa criptografia PGP em Python. Todas as operações criptográficas são delegadas ao GnuPG do sistema.

## Keyring

- O keyring operacional é sempre `~/.gnupg/` (ou `GNUPGHOME` se definido pelo utilizador/ambiente).
- A aplicação não mantém um keyring próprio de chaves privadas.
- Diretórios `secrets/` no projeto, se existirem, **não** são usados automaticamente.

## Descoberta de chaves

- A varredura é **somente leitura**: localiza e identifica; não importa, apaga nem altera o keyring.
- Inspeção de ficheiros usa `gpg --show-keys` com homedir temporário (nunca escreve em `~/.gnupg`).
- Locais por defeito: Desktop/Área de Trabalho, Documents/Documentos, Downloads (nunca `/` inteiro).
- Importação e backup privado só ocorrem após confirmação explícita do utilizador, via GnuPG.

## gpg-agent

- Operações que exigem desbloqueio da chave privada (assinar, descriptografar, exportar privada) dependem do `gpg-agent` e do `pinentry` do sistema.
- A aplicação **não** armazena passphrase em código, `.env`, JSON, YAML, SQLite, logs, cache ou ficheiros de configuração.
- A única exceção de introdução de passphrase na UI é a **geração** de uma nova chave (proteção da chave no GnuPG). Esse valor é efémero e enviado uma vez ao GnuPG.

## PUBLIC KEY vs PRIVATE KEY

| Tipo | Uso |
|------|-----|
| **PUBLIC KEY** | Criptografar para alguém; verificar assinaturas |
| **PRIVATE KEY** | Assinar; descriptografar mensagens destinadas a si |

Exportar “chave” por omissão significa **exportar chave pública**.

Exportar chave privada / backup exige confirmação explícita com aviso forte e gravação apenas no destino escolhido pelo utilizador (diálogo de ficheiro). O material privado **não** é deixado no painel da UI.

## Backup

- Backup de chave privada é operação manual e sensível.
- Não use ficheiros plaintext no projeto como backup operacional.
- Prefira armazenamento cifrado / offline.
- Se existir um ficheiro legado `secrets/pgp-keys.asc` (ou similar) com material privado em texto puro, trate-o como risco: mova para armazenamento seguro e remova cópias desnecessárias.

## Fingerprint

- O identificador de confiança é o **fingerprint completo**.
- A UI apresenta o fingerprint formatado (grupos de 4) e pede confirmação antes de criptografar.
- Não confie apenas em nome ou e-mail.

## Limitações de confiança

Uma assinatura **criptograficamente válida** prova que a chave correspondente assinou os dados.

Isso **não** prova, por si só, que a identidade do dono da chave foi verificada por si (web of trust / contacto fora da banda).

## Clipboard

- Colar/Copiar são funções do sistema.
- Conteúdo sensível no clipboard pode ser lido por outras aplicações.
- A app avisa ao copiar conteúdo sensível; limpe o clipboard quando terminar.
- A app não copia private keys nem passphrases automaticamente.

## Logs

Os logs da aplicação podem registar:

- tipo de operação
- início/fim
- fingerprint público
- status resumido

Os logs **não** devem conter:

- plaintext
- ciphertext completo
- private keys
- passphrases
- clipboard
- conteúdo de ficheiros

## Modelo de ameaça básico

**Protege contra (com GnuPG bem configurado):**

- envio acidental de plaintext se o utilizador usar encrypt corretamente
- exportação acidental de private key sem confirmação
- injeção de comando via `shell=True` (não utilizado)
- testes a corromperem o keyring real (testes usam `GNUPGHOME` temporário)

**Não protege contra:**

- malware com acesso à sessão do utilizador / memória / clipboard
- pinentry comprometido
- confirmação cega de fingerprints
- backups plaintext de chaves privadas guardados em locais inseguros
- adversário com acesso root à máquina

## Permissões

- `umask(0o077)` no arranque do processo
- diretórios `secrets/` criados pela app: `0700`
- ficheiros sensíveis criados pela app: `0600`
- A app **não** faz `chmod -R` em `~/.gnupg`

## Reportar problemas

Reporte problemas de segurança de forma responsável ao mantenedor do projeto, sem publicar chaves privadas, passphrases ou mensagens confidenciais.
