# Загрузка RSA ключей в .NET

Существуют нескоолько методов загрузка RSA ключей и создание соответсвующих крипто объектов в .NET:

## Загрузка RSA из файлов приватного и публичного ключа (PEM)

Создание приватного ключа:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out private-key.pem
```

*rsa_keygen_bits - длина ключа (рекомендуемая длина не менее 2048)*

Создание публичного ключа:

```bash
openssl pkey -in private-key.pem -pubout -out public-key.pem
```

## Загрузка RSA из X.509 (pem, pfx)

Создание самоподписанного сертификата:

```bash
openssl req -new -x509 -key private-key.pem -out cert.pem -days 360
```

Создание PKCS#12 формата файла для хранения приватного ключа и сертификата

```bash
openssl pkcs12 -export -out cert.pfx -inkey private-key.pem -in cert.pem
```


## Загрузка RSA из JWK (HS256 и PS256)

Показан пример, как можно сгенерировать JWK и как из него получить RSA. Показаны два различных алгоритма


## Загрузка из эфемерного сертификата

Создаём самоподписанного сертификата на лету и фоормирование приватного и пбличного ключей