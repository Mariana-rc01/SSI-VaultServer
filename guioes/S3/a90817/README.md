# Guião 1

>> python3 -c "import cryptography; print(cryptography.__version__)"
44.0.1

## Questão 1:

A principal diferença está na geração das chaves nos dois programas.

No otp.py, uso os.urandom() para gerar bytes aleatórios, esta função gera criptograficamente bytes seguros, a aleatoriedade é garantida pelo sistema operacional, tornando as chaves imprevisíveis e seguras.

No bad_otp.py, uso um pseudo-random number generator inseguro, com uma seed fixa, tornando o PRNG previsível e o random.randbyes() não é criptograficamente seguro, visto que é usado para gerar números pseudo-aleatórios.

## Questão 2:

O ataque não contradiz a segurança absoluta do One-Time Pad, pois o OTP só é seguro se a chave for verdadeiramente aleatória. A implementação do bad_otp.py é insegura, pois usa um gerador de número pseudo-aleatórios, o que torna a chave imprevisível.
O ataque realizado não é bem sucedido no OTP, apenas em OTPs mal implementados.