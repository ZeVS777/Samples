# Загрузка ECDSA ключей в .NET

Существуют несколько методов загрузка ECDSA ключей и создание соответствующих криптографических объектов в .NET. Здесь можно найти примеры использоования следующих алгоритмов: ES256, ES384, ES512, ES256K (secP256k1 Kobliz curve)

## Загрузка ECDsa из файлов приватного и публичного PEM ключа (ES256, ES256K)

Создание приватного ключа:

```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out private-key.pem
```

*ec_paramgen_curve - тип эллиптической кривой (openssl ecparam -list_curves)*

Создание приватного ключа для secp256k1:

```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp256k1 -out private-key.secP256k1.pem
```

Создание публичного ключа:

```bash
openssl pkey -in private-key.pem -pubout -out public-key.pem
```

## Загрузка ECDsa из X.509 pem и pfx файлов (ES256, ES256K)

Создание самоподписанного сертификата:

```bash
openssl req -new -x509 -key private-key.pem -out cert.pem -days 360
```

Создание PKCS#12 формата файла для хранения приватного ключа и сертификата

```bash
openssl pkcs12 -export -out cert.pfx -inkey private-key.pem -in cert.pem
```


## Загрузка ECDsa из JWK (ES256, ES256K)

Показан пример, как можно сгенерировать JWK и как из него получить ECDSA. Показаны два различных алгоритма


## Загрузка из эфемерного сертификата (ES256, ES384, ES512, ES256K)

Создаём самоподписанного сертификата на лету и формирование приватного и публичного ключей


## Использование CryptoProviderFactory для создания подписи и её проверки (ES256, ES384, ES512, ES256K)

**Microsoft.IdentityModel.Tokens** предлагает удобный инстрмент для проведения процедуры подтверждения валидности подписи.
Однако он поддерживает ограниченный [набор алгоритмов](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/wiki/Supported-Algorithms), среди которых нет ES256K. Для поддержки алгоритмов, не поддерживаемых стандартными инструментами, можно их расширить: см. CustomCryptoProvider.cs.
