# Guião 5

## Questão 1:

A execução do programa chacha20_int_attack.py sobre um criptograma produzido pelo pbenc_chacha20_poly1305.py será com grande probabilidade ineficaz, porque o
algoritmo ChaCha20Poly1305 utiliza uma autenticação de mensagem com o Poly1305, o que garante a integridade dos dados cifrados. Logo qualquer alteração no criptograma sem o conhecimento da chave secreta resultará numa falha de verificação de autenticidade.


## Questão 2:

A sugestão de usar m2 com mais de 16 bytes deve-se ao facto de que se m2 tiver exatamente 16 bytes, o CBC-MAC apenas irá produzir um único bloco cifrado como tag, o que torna mais difícil explorar
a vulnerabilidade da extensão de comprimento. Com mais de 16 bytes, o atacante pode remover o último bloco de m2 e construir uma nova mensagem m3 que reutiliza a estrutura de cifragem de m1, o que garante que o último bloco da cifra de m3 coincida com o de m2, de modo que é validado com t2.
