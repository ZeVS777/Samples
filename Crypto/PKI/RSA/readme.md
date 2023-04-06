# �������� RSA ������ � .NET

���������� ���������� ������� �������� RSA ������ � �������� �������������� ������ �������� � .NET:

## �������� RSA �� ������ ���������� � ���������� ����� (PEM)

�������� ���������� �����:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out private-key.pem
```

*rsa_keygen_bits - ����� ����� (������������� ����� �� ����� 2048)*

�������� ���������� �����:

```bash
openssl pkey -in private-key.pem -pubout -out public-key.pem
```

## �������� RSA �� X.509 (pem, pfx)

�������� ���������������� �����������:

```bash
openssl req -new -x509 -key private-key.pem -out cert.pem -days 360
```

�������� PKCS#12 ������� ����� ��� �������� ���������� ����� � �����������

```bash
openssl pkcs12 -export -out cert.pfx -inkey private-key.pem -in cert.pem
```


## �������� RSA �� JWK (HS256 � PS256)

������� ������, ��� ����� ������������� JWK � ��� �� ���� �������� RSA. �������� ��� ��������� ���������


## �������� �� ���������� �����������

������ ���������������� ����������� �� ���� � ������������� ���������� � ��������� ������