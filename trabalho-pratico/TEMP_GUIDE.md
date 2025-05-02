# Guia para correr o código com isolamento:

1. Correr o script `setup.sh` para criar os users no sistema:

```bash
chmod +x scripts/setup.sh
sudo ./scripts/setup.sh
```

2. Correr o script `init_db_and_storage.py` para fazer o chown dos ficheiros:

```bash
sudo python3 scripts/init_db_and_storage.py
```

3. Dar permissão de setuid ao python3:

```bash
sudo setcap cap_setuid+ep $(which python3)
```

4. Correr o servidor e o cliente normalmente e utilizar como habitual:

```bash
python3 -m server.server
python3 -m client.client
```

5. Para voltar a ter permissões sobre os ficheiros (**é preciso fazer isto obrigatoriamente antes de fazer qualquer operação com o git**):

```bash
sudo python3 scripts/restore_file_ownership.py
```

6. Caso queiram apagar os users criados para o isolamento, podem correr o seguinte comando (**podem escolher apagar os ficheiros associados, não recomendo**):

```bash
chmod +x scripts/teardown.sh
sudo ./scripts/teardown.sh
```
