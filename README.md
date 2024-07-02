# The open Open Banking Brasil project - Mock Payment API's
Exemplo de implementação das API's de pagamento para execução dos testes de segurança do o2b2-auth-server e funcionais do o2b2-fido-server

## Introdução
Este projeto faz uma implementação mínima das API's de Pagamento V3 para execução dos testes de segurança FAPI OP Brazil Open Finance (FAPI-BR v2) e das API's de Enrollment V1 para execução dos testes funcionais do servidor FIDO

## Executando o projeto
Siga os passos abaixo para execução deste projeto

### Clonando o repositório
Faça o clone do projeto no servidor onde a aplicação será utilizada
```
git clone https://github.com/ranierimazili/o2b2-payment-apis.git
```

### Criando os certificados para TLS
Como este serviço é utilizado apenas para testes e fica protegido por um proxy, os certificados https são gerados em tempo de execução através da bilbioteca selfsigned.

### Criando o certificado de assinatura
Crie o certificado de assinatura conforme documentado no [Guia de Operação do Diretório Central](https://openfinancebrasil.atlassian.net/wiki/spaces/OF/pages/17378602/Guia+de+Opera+o+do+Diret+rio+Central).

Copie a chave privada para o diretório src/certs e dê o nome signing.key para o arquivo ou caso prefira utilizar outro path e nome de arquivo, realize o apontamento para o caminho correto no arquivo .env.

### Configurando as varíaveis de ambiente
Edite o arquivo .env preenchendo todas as variáveis.
> **Atenção**: Se você está rodando na sua máquina local, provavelmente as únicas varíaveis que você precisará editar serão _ORGANISATION_ID_ e _SIGNING_CERT_KID_

### Instale as dependências
```
npm i
```

### Execute o projeto
```
npm run start
```