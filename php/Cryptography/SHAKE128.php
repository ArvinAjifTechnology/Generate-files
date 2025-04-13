<?php

namespace Cryptography;

class SHAKE128
{
    private static function keccak($rate, $capacity, $input, $outputLength, $suffix)
    {
        // State adalah array 25 elemen (5x5)
        $state = array_fill(0, 25, gmp_init(0));

        // Menghitung ukuran blok (rate dibagi 8 untuk mendapatkan byte)
        $rateInBytes = $rate / 8;

        // Mengisi input dengan padding
        $input .= chr($suffix);
        $input .= str_repeat(chr(0x00), ($rateInBytes - (strlen($input) % $rateInBytes)) % $rateInBytes);
        $input[strlen($input) - 1] = chr(ord($input[strlen($input) - 1]) | 0x80);

        // Memproses blok input ke dalam state
        for ($i = 0; $i < strlen($input); $i += $rateInBytes) {
            for ($j = 0; $j < $rateInBytes / 8; ++$j) {
                $data = substr($input, $i + $j * 8, 8);
                $val = gmp_import($data, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
                $state[$j] = isset($state[$j]) ? gmp_xor($state[$j], $val) : $val;
            }

            // Panggil fungsi keccakf untuk state
            self::keccakf($state);
        }

        // Menghasilkan output dari state
        $output = '';
        while (strlen($output) < $outputLength) {
            for ($i = 0; $i < $rateInBytes / 8 && strlen($output) < $outputLength; ++$i) {
                $output .= gmp_export($state[$i], 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
            }
            if (strlen($output) >= $outputLength) break;

            // Panggil lagi keccakf untuk iterasi berikutnya
            self::keccakf($state);
        }

        return substr($output, 0, $outputLength);
    }

    // Fungsi keccakf yang memodifikasi state berdasarkan algoritma
    private static function keccakf(&$state)
    {
        static $R = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44];
        static $RC = [
            1,
            0x8082,
            0x800000000000808A,
            0x8000000080008000,
            0x808B,
            0x80000001,
            0x8000000080008081,
            0x8000000000008009,
            0x8A,
            0x88,
            0x80008009,
            0x8000000A,
            0x8000808B,
            0x800000000000008B,
            0x8000000000008089,
            0x8000000000008003,
            0x8000000000008002,
            0x8000000000000080,
            0x800A,
            0x800000008000000A,
            0x8000000080008081,
            0x8000000000008080,
            0x80000001,
            0x8000000080008008
        ];

        // Keccak main rounds
        for ($round = 0; $round < 24; ++$round) {
            $C = [];
            // Step 1: C = A + B + C + D + E
            for ($x = 0; $x < 5; ++$x) {
                $C[$x] = gmp_xor($state[$x], $state[$x + 5]);
                $C[$x] = gmp_xor($C[$x], $state[$x + 10]);
                $C[$x] = gmp_xor($C[$x], $state[$x + 15]);
                $C[$x] = gmp_xor($C[$x], $state[$x + 20]);
            }

            // Step 2: D = C + (C left rotate 1)
            $D = [];
            for ($x = 0; $x < 5; ++$x) {
                $D[$x] = gmp_xor($C[($x + 4) % 5], self::rotl64($C[($x + 1) % 5], 1));
            }

            // Step 3: Apply D to state
            for ($x = 0; $x < 5; ++$x) {
                for ($y = 0; $y < 5; ++$y) {
                    $state[$x + 5 * $y] = gmp_xor($state[$x + 5 * $y], $D[$x]);
                }
            }

            // Step 4: Permutation
            $B = [];
            for ($x = 0; $x < 5; ++$x) {
                for ($y = 0; $y < 5; ++$y) {
                    $B[$y + 5 * ((2 * $x + 3 * $y) % 5)] = self::rotl64($state[$x + 5 * $y], $R[$x + 5 * $y] ?? 0);
                }
            }

            // Step 5: Apply non-linear transformation
            for ($i = 0; $i < 25; ++$i) {
                $state[$i] = gmp_xor($B[$i], gmp_and(gmp_not($B[($i + 1) % 5 + 5 * intdiv($i, 5)]), $B[($i + 2) % 5 + 5 * intdiv($i, 5)]));
            }

            // Step 6: Apply round constant
            $state[0] = gmp_xor($state[0], gmp_init($RC[$round], 10));
        }
    }

    // Fungsi rotasi kiri untuk 64-bit
    private static function rotl64($x, $n)
    {
        $mask = gmp_init("FFFFFFFFFFFFFFFF", 16); // Mask untuk memastikan 64-bit
        $left = gmp_and(gmp_mul($x, gmp_pow(2, $n)), $mask);
        $right = gmp_and(gmp_div_q($x, gmp_pow(2, 64 - $n)), $mask);
        return gmp_or($left, $right);
    }

    // Fungsi hash utama untuk SHAKE128
    public static function hash($input, $length)
    {
        return self::keccak(128, 256, $input, $length, 0x1F);
    }

    // Fungsi untuk menghasilkan hash dalam format hex
    public static function hashHex($input, $length)
    {
        return bin2hex(self::hash($input, $length));
    }
}
