# Trabalho Prático

## Servidor

```bash
python3 -m server.server
```

## Cliente

```bash
python3 -m client.client ./certificates/VAULT_CLIn.p12

```

Being n between 1 and 3 for now

# Updates - Version 15-04-2025
There's some differences in our project logic due to the login/certification authority:

    - The server and the CA already have their corresponding .p12 file;
    - The server now acts an another CA client, which means, that its .p12 file is called: VAULT_CLIS.p12, being the S also the common_name, for now;
    - The CA is totally independent and we should take into consideration that it is always running as a daemon (even though we don't need it anymore after having the corresponding .p12 file)
    - The client authentication is made via CLI
    - We ALWAYS need to have the VAULT_CA.crt already exported so that it is possible to validate the certificates throw the CA.

New runnig methods:

## Servidor

```bash
python3 -m server.server
```

## Cliente

```bash
python3 -m client.client [TLSv1.3 | TLSv1.2]

```

## CA

```bash
cd certification-authority
python3 ca_daemon.py

```

# Note

Please be **careful** that the CL1 .p12 file is no longer the same, so the information we have been using it's like it is from ANOTHER user, please delete it and recreate it again according to your needs.