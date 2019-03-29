# apache-scitoken

This implements a Scitoken authorization module for Apache

Install [scitoken-cpp](https://github.com/scitokens/scitokens-cpp)

Move scitokens-cpp/src/scitokens.h to your include directory
In /src, compile the module:
```
$ apxs -i -a -c scitoken.c -lSciTokens
$ cat /etc/apache2/mods-enabled/auth_scitokenX.load
LoadModule auth_scitokenX_module /usr/lib/apache2/modules/scitoken.so
```
Modify your Apache configeration file. An example is provided, /config(Ubuntu 16.04.6 LTS)
Restart Apache
