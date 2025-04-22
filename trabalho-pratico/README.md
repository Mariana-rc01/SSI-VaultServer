# Relatório de Projeto: Serviço de Cofre Seguro

**Data:** 02/05/2025 | **Disciplina:** Segurança em Sistemas Informáticos | **Curso:** Licenciatura em Engenharia Informática

### Autores

| Número | Nome                              |
|--------|-----------------------------------|
| 104100 | Hélder Ricardo Ribeiro Gomes      |
| 90817  | Mariana Rocha Cristino            |
| 104082 | Pedro Figueiredo Pereira          |
---

## Índice

1. [Introdução](#introdução)
2. [Descrição Geral do Projeto](#descrição-geral-do-projeto)
3. [Objetivos](#objetivos)
4. [Levantamento de Requisitos](#levantamento-de-requisitos)
   1. [Funcionais](#funcionais)
   2. [Segurança](#segurança)
5. [Modelação de Ameaças (Threat Model)](#modelação-de-ameaças-threat-model)
   1. [Identificação de Ameaças](#identificação-de-ameaças)
   2. [Diagrama de Fluxo de Dados e Barreiras](#diagrama-de-fluxo-de-dados-e-barreiras)
6. [Plano de Implementação](#plano-de-implementação)
   1. [Estabelecimento da comunicação servidor cliente](#estabelecimento-da-comunicação-servidor-cliente)
   2. [Aplicação do protocolo criptográfico Diffie-Hellman](#aplicação-do-protocolo-criptográfico-Diffie-Hellman)
   3. [Atualização do protocolo criptográfico base para Station-To-Station](#atualização-do-protocolo-criptográfico-base-para-Station-To-Station)
   4. [Estruturação do processo de serialização/deserialização](#estruturação-do-processo-de-serialização/deserialização)
   5. [Implementação dos comandos propostos](#implementação-dos-comandos-propostos)
   6. [Conceção de extras](#conceção-de-extras)
7. [Extras](#extras)
   1. [Autoridade Certificadora Própria](#autoridade-certificadora-própria)
   2. [Sistema de Registo de Logs](#sistema-de-registo-de-logs)
   3. [Autenticação Baseada em Ficheiros P12](#autenticação-baseada-em-ficheiros-p12)
   4. [Protocolo de Comunicação em JSON](#protocolo-de-comunicação-em-json)
   5. [Possibilidade de execução do comando share para grupos](#possibilidade-de-execução-do-comando-share-para-grupos)
8. [Manual de utilização](#manual-de-utilização)
9. [Conclusões](#conclusões)
10. [Referências](#referências)

---

## Introdução

_Breve contextualização da importância de garantir confidencialidade, integridade e disponibilidade num serviço de cofre seguro._

## Descrição Geral do Projeto

_Descrição sucinta do serviço: cofre pessoal, grupos, armazenamento e partilha de ficheiros._

## Objetivos

- Garantir confidencialidade do conteúdo armazenado
- Assegurar integridade e autenticidade das operações
- Disponibilizar interface CLI simples e intuitiva

## Levantamento de Requisitos

_Lista de requisitos funcionais e de segurança, com prioridades e justificações._

### Funcionais

      Exemplo: O serviço deve permitir que cada utilizador se registe.

### Segurança

      Descrever para cada uma das palavras-chave do enunciado: autenticidade, integridade e confidencialidade

## Modelação de Ameaças (Threat Model)

### Identificação de Ameaças

_Enumeração das principais ameaças (STRIDE)._

### Diagrama de Fluxo de Dados e Barreiras

_Inserir DFD simplificado e definição das barreiras de segurança._

## Plano de Implementação

### Estabelecimento da comunicação servidor cliente

### Aplicação do protocolo criptográfico Diffie-Hellman

### Atualização do protocolo criptográfico base para Station-To-Station

### Estruturação do processo de serialização/deserialização

### Implementação dos comandos propostos

### Conceção de extras

## Extras

### Autoridade Certificadora Própria

_Execução como daemon para emissão e validação de certificados X.509._

### Sistema de Registo de Logs

_Arquitetura do serviço de logs: formato e armazenamento._

### Autenticação Baseada em Ficheiros P12

_Utilização de keystores PKCS#12 para identificação (cliente/servidor)._

### Protocolo de Comunicação em JSON

_Definição de mensagens JSON para operações (add, list, share, ...)._

### Possibilidade de execução do comando share para grupos

_Descrição do motivo do aparecimento do comando e provar a praticidade do mesmo._

## Manual de utilização

_Explicação de como deve ser o executado e guia de utilização de exemplos já disponíveis._

> Para já disponibilizo a parte relevante do nosso README.md antigo.

```
Server: python3 -m server.server

Client: python3 -m client.client

CA: cd certification-authority && python3 ca_daemon.py
```

## Conclusões

_Resumo das decisões tomadas e perspetivas de melhorias futuras._

## Referências

- Enunciado do Projeto (SSI).
- [Cloudflare Learning](https://www.cloudflare.com/learning/)
- ...
