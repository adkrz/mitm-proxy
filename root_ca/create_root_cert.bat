set OPENSSL=C:\Program Files\Git\mingw64\bin\openssl.exe
set ROOT_NAME=MITM_Proxy_Root_CA
set ORGANIZATION_NAME=Test
set CERT_NAME=MITM_Proxy_Server

rem Generate root CA cert and key
rem this one is to be imported into browser trust store
"%OPENSSL%" req -x509 -nodes -newkey RSA:2048 -keyout root-ca.key -days 365 -out root-ca.crt -subj /C=PL/ST=Never/L=Land/O=%ORGANIZATION_NAME%/CN=%ROOT_NAME%

rem Generate server private key and cert. signing request
"%OPENSSL%" req -nodes -newkey rsa:2048 -keyout server.key -out server.csr -subj /C=PL/ST=Never/L=Land/O=%ORGANIZATION_NAME%/CN=%CERT_NAME%

rem Step 3 is from code - based on server CSR and root CA, generate .ext file and certificate for a particular domain

rem Example ext:

rem subjectAltName = DNS:example.com
rem authorityKeyIdentifier = keyid,issuer
rem basicConstraints = CA:FALSE
rem keyUsage = digitalSignature, keyEncipherment
rem extendedKeyUsage=serverAuth

rem Example certificate for target server:
rem "%OPENSSL%" x509 -req -CA root-ca.crt -CAkey root-ca.key -in server.csr -out {cert_file} -days 365 -CAcreateserial -extfile {ext_file}
pause

