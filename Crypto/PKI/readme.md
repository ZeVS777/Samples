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
