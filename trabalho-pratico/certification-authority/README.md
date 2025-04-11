# Exemplo de CA Daemon, Servidor TLS & Cliente TLS

Este projeto demonstra uma implementação simples de:
- Uma **Autoridade Certificadora (CA)** rodando como daemon, que armazena a sua private key e certificado num ficheiro PKCS#12 (p12).
- Um **Servidor TLS** que gera o seu par de chave/CSR se necessário, solicita um certificado assinado ao daemon da CA e inicia um servidor TLS para teste.
- Um **Cliente TLS** que se conecta ao servidor utilizando TLS, verifica o certificado do servidor contra o certificado da CA e imprime a resposta recebida.

---

## Componentes

- **ca_daemon.py**  
  Roda como daemon. Ao iniciar, carrega a CA do ficheiro `ca.p12` (ou cria um novo se não existir). Fica à escuta no endereço e porta (default: `localhost:8000`) para receber pedidos de assinatura de CSR e responder com certificados assinados.

- **server.py**  
  - Verifica se já existem os ficheiros `server_key.pem`, `server_csr.pem` e `server_cert.pem`.
  - Se não existirem, gera uma nova chave e CSR.
  - Envia o CSR para o CA daemon para receber um certificado assinado.
  - Inicia um servidor TLS (na porta `8443`) que ecoa mensagens recebidas.

- **client.py**  
  Conecta-se ao servidor TLS, envia uma mensagem e exibe a resposta recebida. O cliente utiliza o certificado da CA (`ca_cert.pem`) para verificar o certificado do servidor.

---

## Pré-requisitos

- Python 3.6 ou superior.
- Biblioteca `cryptography` (instalar com `pip install cryptography`).
- Ficheiros gerados automaticamente:
  - `ca.p12` – Armazena a chave e o certificado da CA.
  - `server_key.pem`, `server_csr.pem`, `server_cert.pem` – Utilizados pelo servidor.
  - `ca_cert.pem` – Certificado da CA no formato PEM. Caso não o tenhas, extrai-o do `ca.p12` com o comando:

    ```bash
    openssl pkcs12 -in ca.p12 -nokeys -out ca_cert.pem -passin pass:capassword
    ```

---

## Instruções

### 1. Iniciar o CA Daemon

Abra um terminal e execute:

```bash
python ca_daemon.py
```

O daemon irá:
- Carregar ou criar a CA (guardada em `ca.p12`).
- Ficar à escuta no endereço `localhost:8000` para receber pedidos de CSR.

### 2. Iniciar o Servidor TLS

Em outro terminal, inicie o servidor:

```bash
python server.py
```

Se os ficheiros do servidor ainda não existirem, o script:
- Gera uma chave privada e um CSR.
- Envia o CSR para o CA daemon para obter um certificado.
- Guarda os ficheiros `server_key.pem`, `server_csr.pem` e `server_cert.pem`.
- Coloca o servidor TLS à escuta na porta `8443`.

### 3. Preparar o Ficheiro do Certificado da CA

Certifique-se de que o ficheiro `ca_cert.pem` existe para o cliente. Caso não exista, extraia-o do ficheiro `ca.p12`:

```bash
openssl pkcs12 -in ca.p12 -nokeys -out ca_cert.pem -passin pass:capassword
```

### 4. Executar o Cliente TLS

Em um terceiro terminal, execute:

```bash
python client.py
```

O cliente irá:
- Conectar-se ao servidor TLS.
- Enviar uma mensagem de teste.
- Imprimir a resposta do servidor.

---
