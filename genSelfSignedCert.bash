openssl genrsa -des3 -out server.key 1024
openssl req -new -key server.key -out server.csr
cp server.key server.key.org
openssl rsa -in server.key.org -out server.key.nopassphrase
openssl x509 -req -days 365 -in server.csr -signkey server.key.nopassphrase -out server.crt

