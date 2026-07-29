# Password Hash Java

Projeto desenvolvido para estudar o funcionamento do armazenamento seguro de senhas.

## Funcionalidades

- SHA-256
- Salt aleatório
- Hardening (10.000 iterações)
- Comparação segura

## Tecnologias

- Java

## Estrutura

```
Hash
├── encode()
├── compare()
└── calculateHash()
```

## Objetivo

Este projeto foi desenvolvido para compreender o funcionamento interno da geração de hash para senhas.

⚠️ Em aplicações reais, recomenda-se utilizar algoritmos específicos como Argon2, bcrypt ou scrypt.
