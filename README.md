# apache-scitoken

Authentication module for Apache httpd with [Scitoken].(scitoken.org)

The authentication process is carried out by an authentication provider and specified by /src/scitoken.c.

The module will check the request token against a list of issuers provided by the Apache configuration file.

There are built-in checks for issuers, expiration data, and algorithm but by default, only issuer check is enabled.

Install [scitoken-cpp](https://github.com/scitokens/scitokens-cpp)

Move scitokens-cpp/src/scitokens.h to your include directory

In /src, compile the module:
```
$ apxs -i -a -c scitoken.c -lSciTokens
$ cat /etc/apache2/mods-enabled/auth_scitokenX.load
LoadModule auth_scitokenX_module /usr/lib/apache2/modules/scitoken.so
```
Modify your Apache configeration file.

An example is provided, /config(Ubuntu 16.04.6 LTS)

In the example, the only issuer is "https://demo.scitokens.org"

Restart Apache
