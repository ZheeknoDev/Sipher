# Welcome to Sipher
A simple PHP encryption library

[![Generic badge](https://img.shields.io/badge/php-7.x-green.svg)]() [![GitHub tags](https://img.shields.io/github/v/tag/ZheeknoDev/Sipher)](https://GitHub.com/ZheeknoDev/Sipher/tags/) [![Generic badge](https://img.shields.io/badge/package-sipher-orange.svg)](https://packagist.org/packages/zheeknodev/sipher) [![GitHub license](https://img.shields.io/github/license/ZheeknoDev/ASPRA)](https://github.com/ZheeknoDev/ASPRA/blob/main/LICENSE)

# Feature
- Generate a random string
- Generate a random password
- Hashing the password
- Verifying password
- One-way encryption a string
- Verifying the one-way encrypted string
- Generate random encrypt string
- Encryption
- Verifying the encryption

# Getting Started
install composer package
```sh
composer require zheeknodev/sipher 1.0
```
./index.php
```sh
<?php
    // Autoload from composer
    require(__DIR__.'/vendor/autoload.php');
    
    $app = new \Sipher\Sipher('Your some secret words');
    
    // coding something here
```
Insert **"Your some secret words"** as a secret key when calling new an object class.
If You don't have a secret key, use **\Sipher\Sipher::randomString(32);** to generate a random string as a secret key.

## Generate a random string
```sh
$secret_key = \Sipher\Sipher::randomString(32); 

// output -> bkkaxPf39N8okOcn4RSi601LuFBDHnCK
```

## Generate a random password
You can adjust the length of characters, for example, is 10 chars.
```sh
$app->get_random_password(10);

// output -> qhaQ29xr6v
```

## Hashing the password
```sh
$password_hash = $app->get_password_hash("Your password");

// output -> JDJ5JDEwJE5tdkVvcXl3TU9RekwzL0g0blEwbnVmLzJXUjl4a2VSRDdBVzJBN2JXMkltYVF1UjVHdzRT
```

### Verifying password
Return the result as *boolean*
```sh
$password_hash = "JDJ5JDEwJE5tdkVvcXl3TU9RekwzL0g0blEwbnVmLzJXUjl4a2VSRDdBVzJBN2JXMkltYVF1UjVHdzRT";

// result will return as boolean, TRUE and FASLE
$verifying_password = $app->get_password_verify("Your password", $password_hash);

// output -> true
```

## One-way encryption a string
```sh
$crypt = $app->get_crypt('password');

// output -> 0e7ef28192db0a0f10b8f35ce944801a0ba2e397f3af28b292202f1eda52f5cb
```

### Verifying the one-way encrypted string
Return the result as *boolean*
```sh
$crypt = "0e7ef28192db0a0f10b8f35ce944801a0ba2e397f3af28b292202f1eda52f5cb";

// result will return as boolean, TRUE and FASLE
$crypt_verify = $app->get_crypt_verify('password', $crypt);
```

## Encryption
The result will return as *object* that's
- **encrypted** - the encrypted string
- **check_hash** - the optional string use to decrypt 
- **key** - the secret key use to decrypt
```sh
$result = $app->get_random_encrypt();
```
If you need insert your word to encrypt
```sh
$result = $app->get_string_encrypt("your word");
```
output
```sh
print_r($result);

// Object
stdClass Object (
	["encrypted"] => "646e6842533149.......d // it's too long
	["check_hash"] => 4e44466d4e6a4a69........s 
	["key"] => NTIyOWNmNTFlZjk5YTY0NDNmNDA1YmM2NDdjZGRiZDk=
)
```
### Verifying encryption
Return the result as *boolean*
```sh
// From the previous example
$encrypt_string = $result->encrypted;
$encrypt_check_hash = $result->ecrypt_check_hash;
$encrypt_key = $result->encrypt_key;

// result will return as boolean, TRUE and FASLE
$app->get_verify_encrypt($encrypt_string,$encrypt_check_hash, $encryt_key); 
```

# License
(MIT License)

Copyright (c) 2020 ZheeknoDev (million8.me@gmail.com)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

