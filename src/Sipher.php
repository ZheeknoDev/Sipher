<?php

namespace Sipher;

final class Sipher
{
    private const CIPHER = 'aes-256-cbc';
    private const HASHING = 'ripemd256';

    private $secret;
    private $cipher;
    private $cipher_iv;
    private $hashing;

    public function __construct(string $someString)
    {
        $this->secret = $someString;
        $this->set_default_cipher(self::CIPHER);
        $this->set_default_hashing(self::HASHING);
    }

    public function __call($method, $arguments)
    {
        if (!empty($this->secret) && in_array($method, get_class_methods($this))) {
            return call_user_func_array([$this, $method], $arguments);
        }
    }

    final public function __debugInfo()
    {
        return;
    }

    /**
     * step to decryption the data
     * @param string $encrypted
     * @param string $key
     * @return string
     */
    private function decryption(string $encrypted, string $key)
    {
        $encrypted = base64_decode(hex2bin($encrypted));
        $secret = $this->secret;
        $iv = hex2bin(base64_decode($key));
        return openssl_decrypt($encrypted, $this->cipher, $secret, 0, $iv);
    }

    /**
     * step to encryption the data
     * @param string $string
     * @param string $secret
     * @return object
     */
    private function encryption(string $string, string $secret)
    {
        $iv = $this->cipher_iv;
        $encrypted = openssl_encrypt($string, $this->cipher, $secret, 0, $iv);
        $hash = bin2hex(base64_encode(hash_hmac($this->hashing, $string, $secret)));
        $encryptIv = base64_encode(bin2hex($iv));
        return (object) ['encrypted' => bin2hex(base64_encode($encrypted)), 'hash' => $hash, 'key' => $encryptIv];
    }

    final public function get_random_encrypt()
    {
        return $this->encryption(self::randomString(32), $this->secret);
    }

    final public function get_string_encrypt(string $string)
    {
        return $this->encryption($string, $this->secret);
    }

    final public function get_verify_encrypt(string $encrypted, string $hash, string $key)
    {
        return hash_equals(hash_hmac($this->hashing, $this->decryption($encrypted, $key), $this->secret), $hash);
    }

    /**
     * Generate randome string
     * @param int $stingLength
     * @return string
     */
    final public static function randomString(int $stringLength): string
    {
        $number = '0123456789';
        $alphabet = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $charaters = (string) implode('', [$number, $alphabet]);
        $maxLength = strlen($charaters) - 1;
        $arrayCharaters = array();

        for ($i = 0; $i < $stringLength; $i++) {
            $n = rand(0, $maxLength);
            array_push($arrayCharaters, $charaters[$n]);
        }
        return (string) implode('', $arrayCharaters);
    }

    /**
     * Set default cipher value
     * @param string $cipher
     * @return void
     */
    private function set_default_cipher(string $cipher): void
    {
        if (in_array(strtolower($cipher), openssl_get_cipher_methods())) {
            $this->cipher = $cipher;
            $this->cipher_iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($cipher));
        } else {
            die("{$cipher} isn't available cipher methods.");
        }
    }

    /**
     * Set default hasing value
     * @param string $hashing
     * @return void
     */
    private function set_default_hashing(string $hashing): void
    {
        $hash_algos = (phpversion() > 7.2) ? hash_hmac_algos() : hash_algos();
        if (in_array(strtolower($hashing), $hash_algos)) {
            $this->hashing = $hashing;
        } else {
            die("{$hashing} isn't a hashing algorithm.");
        }
    }
}
