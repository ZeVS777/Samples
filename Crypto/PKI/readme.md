# PKI Инфраструктура открытых ключей

Показаны примеры исполоьзования набора различных средств (алгоритмов, инстрментов, сервисов) для реализации криптозадач на основе закрытого и открытого ключей: 
создания и проверки подписи, шифрование ключей и содержимого, а так же способы хранения и передачи настроек алгоритмов.

Рекомендации по организации такоой инфраструктур можно найти в [NIST.SP.800-56Ar2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf)

## EC алгоритмы

### Алгоритмы создания и проверки подписи:
 - ES256 - ECDSA, использующая SHA-256 функцию предварительного хэширования и ключ, созданнй на эллиптической кривой P-256. Этот алгоритм описан в [RFC7518](https://www.rfc-editor.org/rfc/rfc7518#page-9).
 - ES256K - ECDSA, использующая SHA-256 функцию предварительного хэширования и ключ, созданнй на эллиптической кривой P-256K. Этот алгоритм описан в [RFC8812](https://www.rfc-editor.org/rfc/rfc8812#name-using-secp256k1-with-jose-a).
 - ES384 - ECDSA, использующая SHA-384 функцию предварительного хэширования и ключ, созданнй на эллиптической кривой P-384. Этот алгоритм описан в [RFC7518](https://www.rfc-editor.org/rfc/rfc7518#page-9).
 - ES512 - ECDSA, использующая SHA-512 функцию предварительного хэширования и и ключ, созданнй на эллиптической кривой P-521. Этот алгоритм описан в [RFC7518](https://www.rfc-editor.org/rfc/rfc7518#page-9).
 
### Эллиптические кривые, которые используют данные алгоритмы:
 - P-256 - secp256r1 NIST кривая описанная в [DSS FIPS PUB 186-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf).
 - SECP256K1 - SEC кривая описанная в [SEC 2: Recommended Elliptic Curve Domain Parameters](https://www.secg.org/sec2-v2.pdf).
 - P-384 - secp384r1 NIST кривая описанная в [DSS FIPS PUB 186-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf).
 - P-521 - secp521r1 NIST кривая описанная в [DSS FIPS PUB 186-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf).

### Алгоритмы ECDH получения общего секретного ключа по имеющимся пары открытый/закрытый ключ на эллиптических кривых
 - ECDH-ES - использование объединяющей функции формирования ключа (Concat KDF)
   1. A128GCM - использование первых 128 бит результата функции KDF для шифрования данных. [RFC7518](https://www.rfc-editor.org/rfc/rfc7518#page-15)
   2. A192GCM - использование первых 192 бит результата функции KDF для шифрования данных. [RFC7518](https://www.rfc-editor.org/rfc/rfc7518#page-15)
   3. A256GCM - использование первых 256 бит результата функции KDF для шифрования данных. [RFC7518](https://www.rfc-editor.org/rfc/rfc7518#page-15)
 - ECDH-ES+A128GCM - оборачивание сгенериванного ключа длиной в 256 бит, с помощью AES , для которой используется 128 первых бит результата функции KDF
   * Для шифрования используется алгоритм A128CBC-HS256 - AES_128_CBC_HMAC_SHA_256 описанный в [RFC7518](https://www.rfc-editor.org/rfc/rfc7518#page-26)
 - ECDH-ES+A192GCM - оборачивание сгенериванного ключа длиной в 384 бит, с помощью AES , для которой используется 192 первых бит результата функции KDF
   * Для шифрования используется алгоритм A192CBC-HS384 - AES_192_CBC_HMAC_SHA_384 описанный в [RFC7518](https://www.rfc-editor.org/rfc/rfc7518#page-26)
 - ECDH-ES+A256GCM - оборачивание сгенериванного ключа длиной в 512 бит, с помощью AES , для которой используется 256 первых бит результата функции KDF
   * Для шифрования используется алгоритм A256CBC-HS512 - AES_256_CBC_HMAC_SHA_512 описанный в [RFC7518](https://www.rfc-editor.org/rfc/rfc7518#page-26)

### Алгоритмы симметричного шифрования ключом, полученным в результате ECDH
 - AES-KW - AES алгооритм шифрования ключа [RFC3394](https://www.rfc-editor.org/rfc/rfc3394).
 - AES-GCM - AES алгоритм шифрования с использованием счётчика с аутентификацией Галуа [NIST SP 800-38d](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
 - AES-CBC - AES алгоритм блоочного шифрования [NIST SP 800-38a](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)
 
### Примеры
 
Примеры загрузки и использования алгоритмов, основанных на эллиптических кривых, можно найти [тут](EC)
 
## RSA алгоритмы

### Алгоритмы шифрования:
 - RSA1_5 - RSAES-PKCS1-V1_5 шифрование ключа, описанное в [RFC8017](https://www.rfc-editor.org/rfc/rfc8017#page-27) и в [RFC7518](https://www.rfc-editor.org/rfc/rfc7518#page-12)
 - RSA-OAEP - RSAES алгоритм, использующий оптимальное асимметричное шифрование с дополнением (OAEP), описанное в [RFC8017](https://www.rfc-editor.org/rfc/rfc8017#page-19) и в [RFC7518](https://www.rfc-editor.org/rfc/rfc7518#page-13), с параметрами, описанными в Section A.2.1. Эти параметры соответсвуют функции шифрования SHA-1 и функции генерации маски MGF1 с SHA-1.
 - RSA-OAEP-256 – RSAES алгоритм, использующий оптимальное асимметричное шифрование с дополнением (OAEP), с хэш функцией SHA-256 и функции генерации маски MGF1 с SHA-256.
 
 ### Алгоритмы создания и проверки подписи:
 - PS256 - RSASSA-PSS с хэш функцией SHA-256 и MGF1 с SHA-256, описанное в [RFC8017](https://www.rfc-editor.org/rfc/rfc8017#page-32) и в [RFC7518](https://www.rfc-editor.org/rfc/rfc7518#page-10).
 - PS384 - RSASSA-PSS с хэш функцией SHA-384 и MGF1 с SHA-384.
 - PS512 - RSASSA-PSS с хэш функцией SHA-512 и MGF1 с SHA-512.
 - RS256 - RSASSA-PKCS-v1_5 с хэш функцией SHA-256, описанное в [RFC8017](https://www.rfc-editor.org/rfc/rfc8017#page-35) и в [RFC7518](https://www.rfc-editor.org/rfc/rfc7518#page-8).
 - RS384 - RSASSA-PKCS-v1_5 с хэш функцией SHA-384.
 - RS512 - RSASSA-PKCS-v1_5 с хэш функцией SHA-512.

 ### Примеры
 
Примеры загрузки и использования алгоритмов, основанных на RSA, можно найти [тут](RSA)
