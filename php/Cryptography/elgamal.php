<?php

namespace Cryptography;

use Exception;

class ElGamal
{
    var $x; // Kunci privat
    var $p; // Bilangan prima
    var $g; // Generator
    var $y; // Kunci publik (y = g^x mod p)
    var $text; // Teks yang akan dienkripsi
    var $cipher; // Cipher untuk dekripsi

    function isPrime($number)
    {
        // 1 is not prime
        if ($number == 1) {
            return false;
        }
        // 2 is the only even prime number
        if ($number == 2) {
            return true;
        }
        // square root algorithm speeds up testing of bigger prime numbers
        $x = sqrt($number);
        $x = floor($x);
        for ($i = 2; $i <= $x; ++$i) {
            if ($number % $i == 0) {
                break;
            }
        }

        if ($x == $i - 1) {
            return true;
        } else {
            return false;
        }
    }

    function generatePublicKey()
    {
        // Menghitung kunci publik
        if (!$this->isPrime($this->p)) {
            echo "[+] Pastikan kolom bilangan prima adalah bilangan prima\n";
            exit("keluar");
        }

        // y = g^x mod p
        $this->y = bcpowmod($this->g, $this->x, $this->p);
        return $this->y;
    }

    function getKey()
    {
        // Menghasilkan kunci publik (y) atau kunci privat (x)
        return $this->y;  // public key
    }

    function pecahString()
    {
        // Memecah teks menjadi array karakter
        return str_split($this->text);
    }

    function getAscii()
    {
        // Mengonversi teks menjadi representasi ASCII
        foreach ($this->pecahString() as $pecahan) {
            $ascii[] = ord($pecahan);
        }
        return $ascii;
    }

    function encrypt()
    {
        $cipher = [];  // Pastikan array kosong untuk menyimpan hasil enkripsi
        // Menggabungkan delta dan gamma menjadi array untuk setiap pesan m
        foreach ($this->getAscii() as $m) {
            $k = $this->getK($m);
            $cipher[] = bcpowmod($this->g, $k, $this->p); // gamma
            $cipher[] = bcmod(bcmul(bcpow($this->getKey(), $k), $m), $this->p); // delta
        }
        $this->cipher = $cipher; // Pastikan menyimpan hasil enkripsi ke dalam $this->cipher
        return $cipher;
    }


    function decrypt($ciphertext)
    {
        if (!is_array($ciphertext)) {
            throw new \Exception("Cipher text must be an array, " . gettype($ciphertext) . " given.");
        }

        $delta = [];
        $gamma = [];
        for ($i = 0; $i < count($ciphertext); $i++) {
            if ($i % 2 != 0) {
                $delta[] = $ciphertext[$i];
            } else {
                $gamma[] = $ciphertext[$i];
            }
        }

        $pangkat = $this->p - 1 - $this->x;
        $hasil = [];

        for ($i = 0; $i < count($gamma); $i++) {
            $hasil[] = chr(bcmod(bcmul($delta[$i], bcpow($gamma[$i], $pangkat)), $this->p));
        }

        return implode('', $hasil);
    }




    function getK()
    {
        return rand(1, ($this->p - 2)); // Random number untuk k
    }
}
