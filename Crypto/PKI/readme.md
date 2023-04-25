# PKI Инфраструктура открытых ключей

Показаны примеры исполоьзования набора различных средств (алгоритмов, инстрментов, сервисов) для реализации криптозадач на основе закрытого и открытого ключей: 
создания и проверки подписи, шифрование ключей и содержимого, а так же способы хранения и передачи настроек алгоритмов.

* Рекомендации по организации такоой инфраструктур можно найти в [NIST.SP.800-56Ar2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf).
* Рекомендации по использовании алгоритмов криптографии в условиях появления квантовых вычислений можно прочитать в [Исследованиях Microsoft]( https://www.microsoft.com/en-us/research/wp-content/uploads/2017/09/1706.06752.pdf) на эту тему.
* Рекомендации по настройкам алгоритмов можно прочитать на сайте [ecrypt](https://www.ecrypt.eu.org/csa/documents/D5.4-FinalAlgKeySizeProt.pdf)

## EC алгоритмы

### Алгоритмы создания и проверки подписи:
 - ES256 - ECDSA, использующая SHA-256 функцию предварительного хэширования и ключ, созданнй на эллиптической кривой P-256. Этот алгоритм описан в [RFC7518](https://datatracker.ietf.org/doc/html/rfc7518#section-3.4).
 - ES256K - ECDSA, использующая SHA-256 функцию предварительного хэширования и ключ, созданнй на эллиптической кривой P-256K. Этот алгоритм описан в [RFC8812](https://www.rfc-editor.org/rfc/rfc8812#name-using-secp256k1-with-jose-a).
 - ES384 - ECDSA, использующая SHA-384 функцию предварительного хэширования и ключ, созданнй на эллиптической кривой P-384. Этот алгоритм описан в [RFC7518](https://datatracker.ietf.org/doc/html/rfc7518#section-3.4).
 - ES512 - ECDSA, использующая SHA-512 функцию предварительного хэширования и и ключ, созданнй на эллиптической кривой P-521. Этот алгоритм описан в [RFC7518](https://datatracker.ietf.org/doc/html/rfc7518#section-3.4).
 
### Эллиптические кривые, которые используют данные алгоритмы:
 - P-256 - secp256r1 NIST кривая описанная в [DSS FIPS PUB 186-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf).
 - SECP256K1 - SEC кривая описанная в [SEC 2: Recommended Elliptic Curve Domain Parameters](https://www.secg.org/sec2-v2.pdf).
 - P-384 - secp384r1 NIST кривая описанная в [DSS FIPS PUB 186-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf).
 - P-521 - secp521r1 NIST кривая описанная в [DSS FIPS PUB 186-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf).

*Безопасность таких кривых можно проверить на сайте [safecurves](https://safecurves.cr.yp.to)*

### Алгоритмы ECDH получения общего секретного ключа по имеющимся пары открытый/закрытый ключ на эллиптических кривых
 - ECDH-ES - использование объединяющей функции формирования ключа (Concat KDF), описанной в [NIST.SP.800-56Ar2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf) раздел 5.8.1 и в [RFC7518](https://datatracker.ietf.org/doc/html/rfc7518#section-4.6.2)
   1. A128GCM - использование первых 128 бит результата функции KDF для шифрования данных. [RFC7518](https://datatracker.ietf.org/doc/html/rfc7518#section-5.3)
   2. A192GCM - использование первых 192 бит результата функции KDF для шифрования данных. [RFC7518](https://datatracker.ietf.org/doc/html/rfc7518#section-5.3)
   3. A256GCM - использование первых 256 бит результата функции KDF для шифрования данных. [RFC7518](https://datatracker.ietf.org/doc/html/rfc7518#section-5.3)
 - ECDH-ES+A128KW - оборачивание сгенериванного ключа длиной в 256 бит, с помощью AES [RFC7518](https://datatracker.ietf.org/doc/html/rfc7518#section-4.6), для которой используется 128 первых бит результата функции KDF
   * Для шифрования используется алгоритм A128CBC-HS256 - AES_128_CBC_HMAC_SHA_256 описанный в [RFC7518](https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.3)
 - ECDH-ES+A192KW - оборачивание сгенериванного ключа длиной в 384 бит, с помощью AES [RFC7518](https://datatracker.ietf.org/doc/html/rfc7518#section-4.6), для которой используется 192 первых бит результата функции KDF
   * Для шифрования используется алгоритм A192CBC-HS384 - AES_192_CBC_HMAC_SHA_384 описанный в [RFC7518](https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.4)
 - ECDH-ES+A256KW - оборачивание сгенериванного ключа длиной в 512 бит, с помощью AES [RFC7518](https://datatracker.ietf.org/doc/html/rfc7518#section-4.6), для которой используется 256 первых бит результата функции KDF
   * Для шифрования используется алгоритм A256CBC-HS512 - AES_256_CBC_HMAC_SHA_512 описанный в [RFC7518](https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.5)

### Алгоритмы симметричного шифрования ключом, полученным в результате ECDH
 - AES-KW - AES алгооритм шифрования ключа [RFC3394](https://datatracker.ietf.org/doc/html/rfc3394).
 - AES-GCM - AES алгоритм шифрования с использованием счётчика с аутентификацией Галуа [NIST SP 800-38d](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
 - AES-CBC - AES алгоритм блоочного шифрования [NIST SP 800-38a](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)
 
### Примеры
 
Примеры загрузки и использования алгоритмов, основанных на эллиптических кривых, можно найти [тут](EC)
 
## RSA алгоритмы

### Алгоритмы шифрования:
 - RSA1_5 - RSAES-PKCS1-V1_5 шифрование ключа, описанное в [RFC8017](https://datatracker.ietf.org/doc/html/rfc8017#section-7.2) и в [RFC7518](https://datatracker.ietf.org/doc/html/rfc7518#section-4.2)
 - RSA-OAEP - RSAES алгоритм, использующий оптимальное асимметричное шифрование с дополнением (OAEP), описанное в [RFC8017](https://datatracker.ietf.org/doc/html/rfc8017#section-7.1) и в [RFC7518](https://datatracker.ietf.org/doc/html/rfc7518#section-4.3), с параметрами, описанными в Section A.2.1. Эти параметры соответсвуют функции шифрования SHA-1 и функции генерации маски MGF1 с SHA-1.
 - RSA-OAEP-256 – RSAES алгоритм, использующий оптимальное асимметричное шифрование с дополнением (OAEP), с хэш функцией SHA-256 и функции генерации маски MGF1 с SHA-256.
 
 ### Алгоритмы создания и проверки подписи:
 - PS256 - RSASSA-PSS с хэш функцией SHA-256 и MGF1 с SHA-256, описанное в [RFC8017](https://datatracker.ietf.org/doc/html/rfc8017#section-8.1) и в [RFC7518](https://datatracker.ietf.org/doc/html/rfc7518#section-3.5).
 - PS384 - RSASSA-PSS с хэш функцией SHA-384 и MGF1 с SHA-384.
 - PS512 - RSASSA-PSS с хэш функцией SHA-512 и MGF1 с SHA-512.
 - RS256 - RSASSA-PKCS-v1_5 с хэш функцией SHA-256, описанное в [RFC8017](https://datatracker.ietf.org/doc/html/rfc8017#section-8.2) и в [RFC7518](https://www.rfc-editor.org/rfc/rfc7518#page-8).
 - RS384 - RSASSA-PKCS-v1_5 с хэш функцией SHA-384.
 - RS512 - RSASSA-PKCS-v1_5 с хэш функцией SHA-512.

### Примеры
 
Примеры загрузки и использования алгоритмов, основанных на RSA, можно найти [тут](RSA)

## Edwards curve алгоритмы, [OKP](https://datatracker.ietf.org/doc/html/rfc8037#section-2)

### Алгоритмы создания и проверки подписи:
 - Ed25519 - EdDSA, использующая SHA-256 функцию предварительного хэширования и ключ, созданнй на эллиптической кривой Ed25519. Этот алгоритм описан в [RFC8037](https://datatracker.ietf.org/doc/html/rfc8037#section-3.1) и в [RFC8032](https://datatracker.ietf.org/doc/html/rfc8032#section-5.1).
 - Ed448 - EdDSA, использующая SHA-256 функцию предварительного хэширования и ключ, созданнй на эллиптической кривой P-256K. Этот алгоритм описан в [RFC8037](https://datatracker.ietf.org/doc/html/rfc8037#section-3.1) и в [RFC8032](https://www.rfc-editor.org/rfc/rfc8032#section-5.2).
 
### Эллиптические кривые, которые используют данные алгоритмы:
 - Curve25519 - криптографическая эллиптическая кривая, описанная в [RFC7748](https://datatracker.ietf.org/doc/html/rfc7748#section-4.1)
 - Ed448-Goldilocks - криптографическая эллиптическая кривая, описанная в [RFC7748](https://datatracker.ietf.org/doc/html/rfc7748#section-4.2)

*Безопасность таких кривых можно проверить на сайте [safecurves](https://safecurves.cr.yp.to)*

### Алгоритмы ECDH получения общего секретного ключа по имеющимся пары открытый/закрытый ключ на эллиптических кривых
 - ECDH-ES - использование объединяющей функции формирования ключа (Concat KDF), описанной в [NIST.SP.800-56Ar2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf) раздел 5.8.1 и в [RFC7518](https://datatracker.ietf.org/doc/html/rfc7518#section-4.6.2)
   1. A128GCM - использование первых 128 бит результата функции KDF для шифрования данных. [RFC7518](https://datatracker.ietf.org/doc/html/rfc7518#section-5.3)
   2. A256GCM - использование первых 256 бит результата функции KDF для шифрования данных. [RFC7518](https://datatracker.ietf.org/doc/html/rfc7518#section-5.3)
 - ECDH-ES+A128KW - оборачивание сгенериванного ключа длиной в 256 бит, с помощью AES [RFC7518](https://datatracker.ietf.org/doc/html/rfc7518#section-4.6), для которой используется 128 первых бит результата функции KDF
   * Для шифрования используется алгоритм A128CBC-HS256 - AES_128_CBC_HMAC_SHA_256 описанный в [RFC7518](https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.3)
 - ECDH-ES+A256KW - оборачивание сгенериванного ключа длиной в 512 бит, с помощью AES [RFC7518](https://datatracker.ietf.org/doc/html/rfc7518#section-4.6), для которой используется 256 первых бит результата функции KDF
   * Для шифрования используется алгоритм A256CBC-HS512 - AES_256_CBC_HMAC_SHA_512 описанный в [RFC7518](https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.5)
   
### Механизмы, использемые при ECDH, основанных на эллиптических кривых Эдвардса
 - X25519 - механизм ECDH алгоритма, оописанный в [RFC7748](https://datatracker.ietf.org/doc/html/rfc7748#section-5).
 - X448 - механизм ECDH алгоритма, оописанный в [RFC7748](https://datatracker.ietf.org/doc/html/rfc7748#section-5).

### Примеры

Примеры загрузки и использования алгоритмов, основанных на кривых Эдвардса, можно найти [тут](OKP)
