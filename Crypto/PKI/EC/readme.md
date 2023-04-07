# Загрузка ECDSA ключей в .NET

Существуют нескоолько методов загрузка ECDSA ключей и создание соответсвующих крипто объектов в .NET:

## Загрузка ECDSA из файлов приватного и публичного ключа (PEM)

Создание приватного ключа:

```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out private-key.pem
```

*ec_paramgen_curve - тип эллиптическоой кривой (openssl ecparam -list_curves)*

Создание публичного ключа:

```bash
openssl pkey -in private-key.pem -pubout -out public-key.pem
```

## Загрузка ECDSA из X.509 (pem, pfx)

Создание самоподписанного сертификата:

```bash
openssl req -new -x509 -key private-key.pem -out cert.pem -days 360
```

Создание PKCS#12 формата файла для хранения приватного ключа и сертификата

```bash
openssl pkcs12 -export -out cert.pfx -inkey private-key.pem -in cert.pem
```


## Загрузка ECDSA из JWK (ES256)

Показан пример, как можно сгенерировать JWK и как из него получить ECDSA. Показаны два различных алгоритма


## Загрузка из эфемерного сертификата

Создаём самоподписанного сертификата на лету и фоормирование приватного и пбличного ключей


## Использование CryptoProviderFactory для создания подписи и её проверки

**Microsoft.IdentityModel.Tokens** предлагает удобный инстрмент для проведения процедуры подтверждения валидности подписи
