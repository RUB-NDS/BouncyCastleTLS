# BouncyCastleTLS
BouncyCastle TLS examples

- Following BC versions are supported: 1.50 - 1.58
- Only RSA keys are supported (using EC keys ends up with an internal error)

Compile with (assuming version 1.56):
```bash
mvn clean install -Dbc.version=1.56
```

Start with:
```bash
java -jar BouncyCastleTLS-1.56-1.0.jar /home/juraj/git/TLS-Docker-Library/certs/keys.jks password ec256 4433
```
