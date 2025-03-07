# Guião 2

## Questão 2:

Usar um nonce fixo numa cifra sequencial traz problemas de segurança graves:
- O nonce é um valor aleatório que deve ser único para cada encriptação com a mesma chave. Este evita que mensagens encriptadas com a mesma chave gerem cifras idênticas. Se o nonce for fixo, temos duas mensagens diferentes encriptadas com a mesma chave que terão a mesma sequência de keystream.

- Bastaria fazer um ataque onde se comparam as duas cifras e inferir informações sobre o texto original.

- Se quem está a atacar souber o conteúdo da mensagem encriptada (ou mesmo parte dela), pode calcular o keystream e usá-lo para decifrar qualquer mensagem que use o mesmo nonce.

- Perdemos a confidencialidade totalmente, pois a segurança do ChaCha20 depende da unicidade do nonce.

## Questão 3:

No AES CTR, o ataque é bem sucedido, se a posição modificada estiver dentro do tamanho do plaintext, altera apenas os bytes que são alvos. Aqui, o keystream é gerado via contador e aplicado com XOR ao plaintext.

NO AES CBC, o ataque geralmente não é bem sucedido, como eu consegui verificar com a minha resolução, pois, devido à dependência entre blocos e o padding, o ataque torna-se inviável. Aqui, cada bloco é encriptado após passar pelo XOR com o ciphertext do bloco anterior, exige padding.
