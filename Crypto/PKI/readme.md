## EC algorithms

Алгоритмы создания и проверки подписи:
 - ES256 - ECDSA, использующая SHA-256 фукнцию предварительного хэширования и ключ, созданнй на эллиптической кривой P-256. Этот алгоритм описан в [RFC7518](https://www.rfc-editor.org/rfc/rfc7518#page-9).
 - ES256K - ECDSA, использующая SHA-256 фукнцию предварительного хэширования и ключ, созданнй на эллиптической кривой P-256K. Этот алгоритм описан в [RFC8812](https://www.rfc-editor.org/rfc/rfc8812#name-using-secp256k1-with-jose-a).
 - ES384 - ECDSA, использующая SHA-384 фукнцию предварительного хэширования и ключ, созданнй на эллиптической кривой P-384. Этот алгоритм описан в [RFC7518](https://www.rfc-editor.org/rfc/rfc7518#page-9).
 - ES512 - ECDSA, использующая SHA-512 фукнцию предварительного хэширования и и ключ, созданнй на эллиптической кривой P-521. Этот алгоритм описан в [RFC7518](https://www.rfc-editor.org/rfc/rfc7518#page-9).
 
 
Эллиптические кривыые, которые исполоьзют данныые алгоритмы:
 - P-256 - NIST кривая описанная в [DSS FIPS PUB 186-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf).
 - SECP256K1 - SEC кривая описанная в [SEC 2: Recommended Elliptic Curve Domain Parameters](https://www.secg.org/sec2-v2.pdf).
 - P-384 - NIST кривая описанная в [DSS FIPS PUB 186-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf).
 - P-521 - NIST кривая описанная в [DSS FIPS PUB 186-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf).
 
 Примеры загрузки и использования можно найти [тут](EC/readme.md)
