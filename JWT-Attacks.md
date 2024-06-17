## Introdução

### Motivação
O tema JWT atraiu a minha atenção durante o PS do início do ano e, desde então, não tive a oportunidade de revisitá-lo. Na proposta de elaborar um material, a oportunidade chegou!


### Referências
- [JWT.io - Introduction to JSON Web Tokens](https://jwt.io/introduction)
- [PortSwigger - JWT attacks](https://portswigger.net/web-security/jwt)
- [Auth0 - JSON Web Tokens](https://auth0.com/docs/secure/tokens/json-web-tokens)
- [Dev.to - Signing and Validating JSON Web Tokens (JWT) For Everyone](https://dev.to/kimmaida/signing-and-validating-json-web-tokens-jwt-for-everyone-25fb)

## JSON Web Tokens (JWT)

### O que é um JWT?

>"JSON Web Token (JWT) é um protocolo ([RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)) que define uma maneira compacta e auto-contida de transmitir informações com segurança, entre partes, como um objeto JSON."
 
Eles possuem características que fornece sigilo e integridade, com uso das **assinaturas** e da **encriptação**, à informação sendo trocada. O payload pode ser assinado algoritmos como o **HMAC**, **RSA** ou **ECDSA**.

### Quando usar?

Geralmente são usados para enviar informações acerca do usuário como parte de uma autenticação, _session handling_ ou controle de acesso. Como toda a informação necessária ao servidor é armazenada _client-side_, o JWT tornou-se uma escolha popular para serviços de alta demanda.

### Formato do JWT

Um token JWT é caracterizado da seguinte maneira:

![Token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI4OTAyODkyMiIsIm5hbWUiOiJHUklTIiwiaWF0Ijo4MTI3OTEyMDB9.MbWztCjkTm6-m-HOoUpNz-GGCZj7rmEDzuRBf0PhQk8](../../MEDIA/Topicos-Web/token-JWT-Apresentação.png)

As suas três partes (separadas por um ponto) são:
#### Header
```
{
  "alg": "HS256",
  "typ": "JWT"
}
```
Encodada em base 64, contém metadados sobre o próprio token, como o algoritmo de assinatura sendo utilizado.


#### Payload
```
{
  "sub": "89028922",
  "name": "GRIS",
  "iat": 812791200
}
```

Também encodada em base 64, retém a "verdadeira" informação que será transmitida, como um nome de usuário.


#### Assinatura 
Possui o segmento que é usado para verificar **integridade** e a **confidencialidade** da informação. É feito um hash dos dois primeiros segmentos (Header e Payload) e, no caso de tokens encriptados, feito uma encriptação em cima desse hash. 

Abaixo, segue uma representação de uma função geradora da assinatura de um token:
```
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload)
)
```

### JWT vs JWE vs JWS
O espectro do JWT foi herdado por dois tokens mais especificados, o JSON Web Signature (JWS) e o JSON Web Encryption (JWE). Ambos representam uma maneira mais concreta de implementar JWT's.

![Diagrama de JWE, JWS e JWT](../../MEDIA/Topicos-Web/jwt-jws-jwe.jpg)

Portanto, um JWT, na maioria das vezes, é utilizado como um JWE ou um JWS. A única diferença entre os dois, é que o JWE é encriptado, enquanto o JWS apenas é encodado.

>O token inserido no segmento "Formato do JWT" é um JWE

---
# Ataques de JWT's

### O que são ataques de JWT?
Ataques de JWT são baseados na manipulação dos dados contidos em um token JWT para fins maliciosos. Geralmente, costumam ser um bypass em autenticações e controles de acesso, se passando por alguém que já foi autentificado.

### Qual o impacto?
Geralmente severo. A manipulação de uma autenticação pode permitir a escalação de um privilégio e/ou a personificção de outros usuários através do controle de suas contas.

---
# Exploitando verificações falhas de assinaturas
Aqui, focaremos em JWS's e vulnerabilidades criadas a partir de más implementações desse token. Por definição, os servidores não armazenam nenhuma informação sobre o token JWT que eles emitem, pois cada token é uma entidade auto-contida. Dentre as vantagens, o grande problema é que o servidor não sabe nada sobre o token original. Portanto, se o servidor não conferir a assinatura, nada impede um atacante de mudar o payload do token a fim de atingir um objetivo malicioso.

### Permitindo assinaturas arbitrárias

As bibliotecas de JWT geralmente fornecem um método para verificar tokens (`verify()`) e outro para decodificar (`decode()`). Ocasionalmente, alguns desenvolvedores não verificam as assinaturas e permitem que payloads fabricados por atacantes cumpram o seu propósito pois esqueceram ou confundiram as funções.

Nesse caso, podemos apenas alterar o conteúdo do payload sem importar-se com a assinatura do token, o que configura uma situação gravíssima.

Recomendo o laboratório [JWT authentication bypass via unverified signature](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-unverified-signature) do PortSwigger para entender melhor como a falha na leitura de assinaturas pode impactar o seu sistema.

### Permitindo tokens sem assinatura

Dentro da header, existe o parâmetro "alg", que contém o algoritmo usado para assinar o token.

    {
        "alg": "HS256",
        "typ": "JWT"
    }

Como o token é um objeto auto-contido, o servidor não tem outra opção a não ser confiar no token inputado pelo usuário. Dessa maneira, o atacante consegue controlar o jeito como o servidor verifica a assinatura do JWT.

Além das diversas maneiras de assinar o JWT, o servidor pode deixá-lo não-seguro, sem designar um algoritmo de assinatura. O parâmetro para `alg` que deixa o token sem assinatura é o `none`. Portanto, quando o header se torna:

    {
        "alg": "none",
        "typ": "JWT"
    }

O token inutiliza o último segmento (mantendo o ponto de divisão entre o payload e a assinatura). 

Recomendo o laboratório [JWT authentication bypass via flawed signature verification](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-flawed-signature-verification) do PortSwigger para compreender a prática dessa técnica.


### Brute-forcing chaves secretas

Como vimos, o token pode ser assinado com algoritmos de assinaturas que possui uma string como passphrase para a decodificação e validação da assinatura, a fim de manter a integridade da informação.

Entretanto, caso a escolha da string seja ruim, a assinatura pode ser facilmente quebrada com programas tipo o [Hashcat](https://hashcat.net/hashcat/). O programa tenta encriptar, diversas vezes, o conteúdo da header e do payload com as palavras de uma wordlist, até encontrar uma correspondência.

Isso significa que, caso você encontre a passphrase, você consegue alterar o hash da mensagem dentro da assinatura para coincidir com um payload alterado, manipulando, assim, o servidor.

Usando o Hashcat, você deve rodar o seguinte comando:

    hashcat -a 0 -m 16500 <jwt> <wordlist>

O programa retornará uma correspondência do tipo (caso encontre uma):

    <jwt>:<passphrase>

Recomendo, para este segmento, a prática do lab [JWT authentication bypass via weak signing key](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-weak-signing-key), do PortSwigger.

### Injeção de parâmetro na header do JWT

Dentre todos os parâmetros da header, somente o `alg` é obrigatório. Na prática, contudo, headers JWT (também conhecidos como JOSE headers) contém outros diversos parâmetros. Alguns parâmtros que são interessante para atacantes são:

- `jwk` (JSON Web Key) - Fornece um objeto JSON integrado (embedded) representando a key.;
- `jku` (JSON Web Key Set URL) - Fornece uma URL a qual os servidores conseguem pegar um set de keys contendo a key certa;
- `kid` (Key ID) - Fornece um ID do qual os servidores conseguem usar para identificar a key certa em casos onde existem múltiplas chaves potenciais. Dependendo do formato da chave, esse parâmetro pode ter um parâmetro `kid` correspondente.

#### Injetando JWT's auto-assinados por meio do parâmetro jwk

O `jwk` nos permite integrar uma chave pública diretamente no token através da formatação JWK.

Tome como exemplo a header:

```
{
    "kid": "ed2Nf8sb-sD6ng0-scs5390g-fFD8sfxG",
    "typ": "JWT",
    "alg": "RS256",
    "jwk": {
        "kty": "RSA",
        "e": "AQAB",
        "kid": "ed2Nf8sb-sD6ng0-scs5390g-fFD8sfxG",
        "n": "yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9m"
    }
}
```

Idealmente, os servidores deveriam usar uma lista limitada de chaves públicas para verificar assinaturas JWT. Entretanto, alguns servidores mal-configurados podem usar qualquer chave que está vinculada ao parâmetro `jwk`.

Nesse sentido, você consegue burlar a verificação usando uma chave RSA privada e depois colocando a chave pública relacionada na header `jwk`. Para isso, deve-se adicionar a header `jwk` e alterar o parâmetro `kid` do JWT para coincidir com o `kid` da chave integrada. 

Como esse ataque envolve muita criptografia, é indicado que você utilize uma ferramenta para automatizar esse processo. O Burp Suite Community conta com a extensão "JWT Editor", que facilita diversas etapas desse ataque.

A fim de praticar, recomendo o laboratório [JWT authentication bypass via jwk header injection](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jwk-header-injection) do PortSwigger.

#### Injetando JWT's auto-assinados por meio do parâmetro jku

Ao invés de inserir chaves na header, o atacante pode inserir um web-server que contém um set JWK de chaves feitas para o ataque através do parâmetro `jku`.

> Um set JWK é um objeto JSON que contém um array de JWK's representando diferentes chaves. Confira um exemplo abaixo:

```
{
    "keys": [
        {
            "kty": "RSA",
            "e": "AQAB",
            "kid": "75d0ef47-af89-47a9-9061-7c02a610d5ab",
            "n": "o-yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9mk6GPM9gNN4Y_qTVX67WhsN3JvaFYw-fhvsWQ"
        },
        {
            "kty": "RSA",
            "e": "AQAB",
            "kid": "d8fDFo-fS9-faS14a9-ASf99sa-7c1Ad5abA",
            "n": "fc3f-yy1wpYmffgXBxhAUJzHql79gNNQ_cb33HocCuJolwDqmk6GPM4Y_qTVX67WhsN3JvaFYw-dfg6DH-asAScw"
        }
    ]
}
```

Sets JWK, como esse, são ocasionalmente expostos publicamente por meio de um endpoint padrão, como `/.well-known/jwks.json`.

Injetando o parâmetro `jku` na header, teremos algo do tipo:
```
{
  "kid": "413caab9-8954-4d04-9abe-27481753421c",
  "alg": "RS256",
  "jku": "https://servidor-de-exemplo.com/jwks.json"
}
```

Tal que o atante substitua o `kid` pelo `kid` da chave inserida no servidor de exploit. Após isso, deve-se assinar novamente o token com a chave fabricada.

Alguns websites podem ter uma whitelist de domínios confiáveis, mas talvez você consiga tirar vantagem das discrepâncias do URL parsing para bypassar esse tipo de filtro. Para isso, recomendo aprofundar-se em SSRF (Server-side Request Forgery).

Recomendo o laboratório [JWT authentication bypass via jku header injection](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jku-header-injection) do PortSwigger para compreensão completa do tema.

#### Injetando JWT's auto-assinados por meio do parâmetro kid

Quando o servidor consulta um set JWK, ele utiliza o parâmetro `kid` para referenciar qual é a chave utilizada pelo token, pois pode ser que ele utilize mais de uma chave apenas. Em outras palavras, o parâmetro `kid` identifica uma chave diretamente.

Contudo, a documentação do JWS não especifica uma estrutura concreta para esse ID - é, somente, uma string arbitrária que o developer escolhe. Por exemplo, eles podem usar o parâmetro `kid` para apontar para uma entrada em uma database ou até mesmo um arquivo.

Se o parâmetro estiver referenciando um arquivo, pode ser que ele seja vulnerável a [directory traversal](https://portswigger.net/web-security/file-path-traversal), o que potencialmente possibilita o atacante a usar um arquivo arbitrário do sistema como chave de verificação. Nesse caso, se o servidor utilizar um algoritmo simétrico de verificação, o atacante pode sinalizar um arquivo que tenha um conteúdo previsível, como o `/dev/null`.

Assim, ele poderá montar uma header dessa maneira:

```
{
    "kid": "../../dev/null",
    "typ": "JWT",
    "alg": "HS256",
    "k": "asGsADas3421-dfh9DGN-AFDFDbasfd8-anfjkvc"
}
```

Tal que a chave de verificação será vazia (caso o arquivo esteja vazio). Assim, basta o atacante assinar o token com uma string vazia, burlando, assim, a sua verificação.

# Proximas Partes
- JWT algorithm confusion
- How to prevent JWT attacks

