# PGP Desk

Aplicação gráfica local para operações OpenPGP usando o **GnuPG do sistema** e o **gpg-agent**.

## Requisitos

- Python 3.10+
- GnuPG (`gpg`) instalado no sistema
- `python-gnupg` (instalado no `.venv`)

## Executar

```bash
./run.sh
```

Ou, com o ambiente virtual ativo:

```bash
source .venv/bin/activate
python app.py
```

## Funcionalidades

- Criptografar (um ou vários destinatários)
- Descriptografar (chave privada do keyring `~/.gnupg`)
- Assinar (clearsign, embutida, detach)
- Verificar assinatura (validade criptográfica ≠ confiança de identidade)
- Assinar + criptografar
- Operações em ficheiros (encrypt/decrypt/sign/verify/sign+encrypt)
- Importar / exportar chave pública
- Exportar chave privada / backup (com confirmação forte)
- Gerar RSA 4096 via GnuPG
- Diagnóstico do ambiente GPG

## Modelo de segurança (resumo)

- Keyring operacional: `~/.gnupg/`
- Autenticação de chave privada: `gpg-agent` / pinentry (a app não guarda passphrase)
- Sem telemetria, sem rede, sem banco de dados
- Ver detalhes em [SECURITY.md](SECURITY.md)

## Testes

Os testes usam um `GNUPGHOME` temporário isolado e **não** alteram o seu keyring real:

```bash
.venv/bin/python -m unittest discover -s tests -v
```

## Estrutura

```text
app.py            # GUI
gpg_service.py    # Fachada sobre GnuPG
run.sh            # Launcher
requirements.txt
tests/            # Testes com keyring isolado
secrets/          # Apenas material local (ignorado pelo Git); não é keyring operacional
```
