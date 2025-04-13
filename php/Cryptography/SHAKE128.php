<?php

namespace Cryptography;

class SHAKE128
{
    private static function keccak($rate, $capacity, $input, $outputLength, $suffix)
    {
        $state = array_fill(0, 25, 0);
        $rateInBytes = $rate / 8;
        $blockSize = 0;

        $input .= chr($suffix);
        $input .= str_repeat(chr(0x00), ($rateInBytes - (strlen($input) % $rateInBytes)) % $rateInBytes);
        $input[strlen($input) - 1] = chr(ord($input[strlen($input) - 1]) | 0x80);

        for ($i = 0; $i < strlen($input); $i += $rateInBytes) {
            for ($j = 0; $j < $rateInBytes / 8; ++$j) {
                $state[$j] ^= unpack('P', substr($input, $i + $j * 8, 8))[1];
            }
            self::keccakf($state);
        }

        $output = '';
        while (strlen($output) < $outputLength) {
            for ($i = 0; $i < $rateInBytes / 8 && strlen($output) < $outputLength; ++$i) {
                $output .= pack('P', $state[$i]);
            }
            if (strlen($output) >= $outputLength) break;
            self::keccakf($state);
        }

        return substr($output, 0, $outputLength);
    }

    private static function keccakf(&$s)
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

        for ($round = 0; $round < 24; ++$round) {
            $C = [];
            for ($x = 0; $x < 5; ++$x) {
                $C[$x] = $s[$x] ^ $s[$x + 5] ^ $s[$x + 10] ^ $s[$x + 15] ^ $s[$x + 20];
            }

            $D = [];
            for ($x = 0; $x < 5; ++$x) {
                $D[$x] = $C[($x + 4) % 5] ^ self::rotl64($C[($x + 1) % 5], 1);
            }

            for ($x = 0; $x < 5; ++$x) {
                for ($y = 0; $y < 5; ++$y) {
                    $s[$x + 5 * $y] ^= $D[$x];
                }
            }

            $B = [];
            for ($x = 0; $x < 5; ++$x) {
                for ($y = 0; $y < 5; ++$y) {
                    $B[$y + 5 * ((2 * $x + 3 * $y) % 5)] = self::rotl64($s[$x + 5 * $y], $R[$x + 5 * $y] ?? 0);
                }
            }

            for ($i = 0; $i < 25; ++$i) {
                $s[$i] = $B[$i] ^ ((~$B[($i + 1) % 5 + 5 * intdiv($i, 5)]) & $B[($i + 2) % 5 + 5 * intdiv($i, 5)]);
            }

            $s[0] ^= $RC[$round];
        }
    }

    private static function rotl64($x, $n)
    {
        return (($x << $n) | ($x >> (64 - $n))) & 0xFFFFFFFFFFFFFFFF;
    }

    public static function hash($input, $length)
    {
        return self::keccak(128, 256, $input, $length, 0x1F);
    }

    public static function hashHex($input, $length)
    {
        return bin2hex(self::hash($input, $length));
    }
}
