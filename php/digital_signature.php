<?php

require 'vendor/autoload.php';

use Exception as GlobalException;
use Zxing\QrReader;
use phpseclib3\Crypt\ElGamal;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\AES;
use phpseclib3\Crypt\DES;
use phpseclib3\Crypt\RSA;
use Endroid\QrCode\QrCode;
use phpseclib3\Crypt\Random;
use Endroid\QrCode\QrOptions;
use Endroid\QrCode\Label\Label;
use phpseclib3\Math\BigInteger;
use Endroid\QrCode\Builder\Builder;
use Endroid\QrCode\Writer\PngWriter;
use Endroid\QrCode\Encoding\Encoding;
use phpseclib3\Crypt\PublicKeyLoader;
use Endroid\QrCode\RoundBlockSizeMode;
use Endroid\QrCode\Label\Font\NotoSans;
use Endroid\QrCode\Label\Font\OpenSans;
use Endroid\QrCode\ErrorCorrectionLevel;
use Endroid\QrCode\Label\LabelAlignment;
use PhpOffice\PhpWord\Shared\ZipArchive;
use Endroid\QrCode\Label\Alignment\LabelAlignmentCenter;

class FileSigner
{

    private $pdo;
    private $results = [];

    public function __construct($dbHost, $dbName, $dbUser, $dbPass)
    {
        try {
            $this->pdo = new PDO("mysql:host=$dbHost;dbname=$dbName", $dbUser, $dbPass);
            $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        } catch (PDOException $e) {
            die("Database connection failed: " . $e->getMessage());
        }
    }

    public function processFolder($folderPath, $algorithm, $mode, $hashMode = null, $blockMode = null, $streamMode = null)
    {
        if (!is_dir($folderPath)) {
            throw new Exception("Folder not found: $folderPath");
        }

        $files = scandir($folderPath);
        $validFiles = [];

        // Kumpulkan file-file yang valid (bukan . atau ..) beserta ukurannya
        foreach ($files as $file) {
            if ($file === '.' || $file === '..') {
                continue;
            }

            $filePath = $folderPath . DIRECTORY_SEPARATOR . $file;
            $fileSize = filesize($filePath);
            $validFiles[] = [
                'path' => $filePath,
                'size' => $fileSize,
                'name' => $file
            ];
        }

        // Urutkan file berdasarkan ukuran dari yang terkecil
        usort($validFiles, function ($a, $b) {
            return $a['size'] - $b['size'];
        });

        $totalFiles = count($validFiles);
        $processedCount = 0;

        // Proses file yang sudah diurutkan
        foreach ($validFiles as $fileInfo) {
            $this->processFile($fileInfo['path'], $algorithm, $mode, $hashMode, $blockMode, $streamMode);

            $processedCount++;
            $progress = round(($processedCount / $totalFiles) * 100);
            echo "Progress: $progress% - Processing: {$fileInfo['name']} (Size: {$fileInfo['size']} bytes)\n";
        }

        return $this->results;
    }

    private function processFile($filePath, $algorithm, $mode, $hashMode = null, $blockMode = null, $streamMode = null)
    {
        ini_set('memory_limit', '4096M');
        $startTotalTime = microtime(true);
        $filename = basename($filePath);
        $extension = pathinfo($filePath, PATHINFO_EXTENSION);
        $fileSizeMB = round(filesize($filePath) / 1024 / 1024, 2);
        $content = '';

        if ($extension === 'txt') {
            $content = file_get_contents($filePath);
        } elseif ($extension === 'pdf') {
            $parser = new \Smalot\PdfParser\Parser();
            $pdf = $parser->parseFile($filePath);
            $content = $pdf->getText();
        } elseif ($extension === 'docx') {
            $phpWord = \PhpOffice\PhpWord\IOFactory::load($filePath);

            foreach ($phpWord->getSections() as $section) {
                $elements = $section->getElements();
                $content .= $this->extractElements($elements);
            }

            // Extract images and QR codes
            $zip = new ZipArchive();
            $QRcontent = " ";

            if ($zip->open($filePath) === TRUE) {
                for ($i = 0; $i < $zip->numFiles; $i++) {
                    $fileName = $zip->getNameIndex($i);

                    if (preg_match('/word\/media\/(.+\.(jpeg|jpg|png|gif|bmp|png))/', $fileName, $matches)) {
                        $imageData = $zip->getFromIndex($i);
                        $tempPath = sys_get_temp_dir() . '/temp_qr_' . $i . '.png';
                        file_put_contents($tempPath, $imageData);

                        try {
                            $qrReader = new QrReader($tempPath);
                            $qrText = $qrReader->text();

                            if (!empty($qrText)) {
                                if (preg_match('/^SIGN-[A-Za-z0-9]+$/', $qrText)) {
                                    $QRcontent .= "\n$fileName\n";
                                    $QRcontent = "\n🔑 [Tanda Tangan Digital Terdeteksi] : $qrText\n";
                                } else {
                                    $QRcontent .= "\n$fileName\n";
                                    $QRcontent .= "\n[QR Code Detected] : $qrText\n";
                                }
                            } else {
                                $base64 = base64_encode($imageData);
                                $content .= "\n$fileName\n";
                                $content .= "\n[Gambar-$i: data:image/png;base64,$base64]\n";
                            }
                        } catch (\Exception $e) {
                            $base64 = base64_encode($imageData);
                            $content .= "\n$fileName\n";
                            $content .= "\n[Gambar-$i: data:image/png;base64,$base64]\n";
                        }

                        unlink($tempPath);
                    }
                }
                $zip->close();
            }
        }

        $content = trim(preg_replace('/\s+/', ' ', $content));
        // Buat content2 untuk efek avalanche
        $content2 = $content;

        // Simulasi perubahan 1 karakter kecil (misalnya ubah huruf ke huruf lain atau tambah titik di akhir)
        if (strlen($content2) > 0) {
            $pos = rand(0, strlen($content2) - 1);
            $content2[$pos] = $content2[$pos] === 'a' ? 'b' : 'a'; // ubah satu huruf saja
        } else {
            $content2 = 'a'; // fallback
        }

        if ($content) {
            $startProcessTime = microtime(true);
            $keys = $this->generateKeys($algorithm);

            // Hash the content
            $hashStart = microtime(true);
            $hash = hash($hashMode, $content);
            // $hash = $content;
            $hashTime = microtime(true) - $hashStart;
            $hash2 = hash($hashMode, $content2);

            // Encrypt the content
            $encryptionStart = microtime(true);
            $encryption = $this->encryptContent(
                $hash,
                $algorithm,
                $keys['public_key'] ?? null,
                $keys['private_key'] ?? null,
                $keys['rsa_public_key'] ?? null,
                $keys['ecdsa_private_key'] ?? null,
                $mode,
                $blockMode,
                $streamMode
            );
            $encryptionTime = microtime(true) - $encryptionStart;
            // var_dump($encryption);
            // var_dump($keys['private_key']);
            // die;
            $encryption2 = $this->encryptContent(
                $hash2,
                $algorithm,
                $keys['public_key'] ?? null,
                $keys['private_key'] ?? null,
                $keys['rsa_public_key'] ?? null,
                $keys['ecdsa_private_key'] ?? null,
                $mode,
                $blockMode,
                $streamMode
            );

            // Decrypt the content
            $decryptionStart = microtime(true);
            $decryption = $this->decryptContent(
                $hash,
                $encryption,
                $algorithm,
                $encryption['iv'] ?? null,
                $keys['private_key'] ?? null,
                $keys['public_key'] ?? null,
                $keys['rsa_private_key'] ?? null,
                $keys['ecdsa_public_key'] ?? null,
                $encryption['encrypted'] ?? null,
                $encryption['signature'] ?? null,
                $mode,
                $blockMode,
                $streamMode,
            );
            $decryptionTime = microtime(true) - $decryptionStart;

            $endProcessTime = microtime(true);
            $totalProcessTime = $endProcessTime - $startProcessTime;
            $verified = isset($decryption['decrypted']) ? $decryption['decrypted'] : $decryption === $hash;

            $entropy_ciphertext  = $this->calculateEntropy(isset($encryption['signature']) ? $encryption['encrypted'] . $encryption['signature'] : $encryption);
            $entropy_plaintext = $this->calculateEntropy($hash);

            // Generate QR Code - fixed version
            $qrData = isset($encryption['signature']) ? $encryption['signature'] : $encryption;

            // Convert binary data to a QR-safe format
            if (is_string($qrData) && !mb_check_encoding($qrData, 'UTF-8')) {
                $qrData = base64_encode($qrData);
            } elseif (is_array($qrData)) {
                $qrData = json_encode($qrData);
            }

            $qrCode = $this->generateQRCode($qrData);

            // Prepare data for database
            $resultData = [
                'filename' => $filename,
                'algorithm' => $algorithm,
                'mode' => $mode,
                'block_mode' => $blockMode,
                'stream_mode' => $streamMode,
                'original_size' => strlen($content),
                'hash' => $hash,
                'hash_time' => $hashTime,
                'message_digest' => $hash,
                'avalanche' => $this->calculateAvalancheEffect(isset($encryption['signature']) ? $encryption['encrypted'] . $encryption['signature'] : $encryption, isset($encryption2['signature']) ? $encryption2['encrypted'] . $encryption2['signature'] : $encryption2),
                'encrypt_time' => $encryptionTime,
                'encrypted_size' => strlen(isset($encryption['signature']) ? $encryption['signature'] : $encryption),
                'entropy_ciphertext' => $entropy_ciphertext,
                'entropy_plaintext' => $entropy_plaintext,
                'decrypt_time' => $decryptionTime,
                'decrypted_size' => strlen(isset($decryption['decrypted']) ? $decryption['decrypted'] : $decryption),
                'verified' => $verified ? 'Valid' : 'Tidak Valid',
                'qr_code' => $qrCode,
                'total_process_time' => $totalProcessTime,
                'file_load_time' => $startProcessTime - $startTotalTime,
                'encryption' => isset($encryption['signature']) ? $encryption['signature'] : $encryption,
                'ciphertext' => is_array($encryption) ? json_encode($encryption) : $encryption,
                'decryption' => isset($decryption['decrypted']) ? $decryption['decrypted'] : $decryption,
                'private_key' => $keys['private_key'] ?? null,
                'public_key' => $keys['public_key'] ?? null,
                'created_at' => date('Y-m-d H:i:s'),
                'updated_at' => date('Y-m-d H:i:s')
            ];

            // Save to database
            $this->saveToDatabase($resultData);

            // Format for results array
            $this->results[] = array_map(function ($value) {
                return is_float($value) ? number_format($value, 6) : $value;
            }, $resultData);
        }
    }
    private function generateQrCode($data): string
    {
        try {
            // Validate and prepare data
            $qrData = $this->prepareQrData($data);

            // Build QR code with proper builder initialization
            return $this->buildQrCode($qrData)->getDataUri();
        } catch (GlobalException $e) {
            // Fallback to error QR code
            return $this->generateErrorQrCode($e->getMessage());
        }
    }

    private function prepareQrData($data): string
    {
        if (is_array($data)) {
            $data = json_encode($data);
        }

        if (is_string($data) && !mb_check_encoding($data, 'UTF-8')) {
            $data = base64_encode($data);
        }

        if (empty($data)) {
            throw new GlobalException('No data provided for QR code');
        }

        // Limit data size to prevent QR code capacity issues
        if (strlen($data) > 2953) { // Max for version 40 QR with low error correction
            $data = substr($data, 0, 2950) . '...';
        }

        return $data;
    }

    private function buildQrCode(string $data)
    {
        // Create a new Builder instance with all required parameters
        $builder = new Builder(
            writer: new PngWriter(),
            data: $data,
            encoding: new Encoding('UTF-8'),
            errorCorrectionLevel: ErrorCorrectionLevel::High,
            size: 200,
            margin: 10,
            roundBlockSizeMode: RoundBlockSizeMode::Margin
        );

        return $builder->build();
    }

    private function generateErrorQrCode(string $errorMessage): string
    {
        try {
            // Truncate error message if too long
            $errorMessage = substr($errorMessage, 0, 100);

            $builder = new Builder(
                writer: new PngWriter(),
                data: "Error: {$errorMessage}",
                errorCorrectionLevel: ErrorCorrectionLevel::High,
                size: 150
            );

            return $builder->build()->getDataUri();
        } catch (GlobalException $e) {
            // Ultimate fallback - very simple QR code
            return 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=';
        }
    }


    private function saveToDatabase($data)
    {
        $sql = "INSERT INTO processed_files2 (
        filename, algorithm, mode, block_mode, stream_mode, original_size, 
        hash, hash_time, message_digest, avalanche, encrypt_time, 
        encrypted_size, entropy_ciphertext, entropy_plaintext, decrypt_time, decrypted_size, verified, 
        qr_code, total_process_time, file_load_time, encryption, ciphertext, 
        decryption, private_key, public_key, created_at, updated_at
    ) VALUES (
        :filename, :algorithm, :mode, :block_mode, :stream_mode, :original_size, 
        :hash, :hash_time, :message_digest, :avalanche, :encrypt_time, 
        :encrypted_size, :entropy_ciphertext, :entropy_plaintext, :decrypt_time, :decrypted_size, :verified, 
        :qr_code, :total_process_time, :file_load_time, :encryption, :ciphertext, 
        :decryption, :private_key, :public_key, :created_at, :updated_at
    )
    ON DUPLICATE KEY UPDATE
        algorithm = VALUES(algorithm),
        mode = VALUES(mode),
        block_mode = VALUES(block_mode),
        stream_mode = VALUES(stream_mode),
        original_size = VALUES(original_size),
        hash = VALUES(hash),
        hash_time = VALUES(hash_time),
        message_digest = VALUES(message_digest),
        avalanche = VALUES(avalanche),
        encrypt_time = VALUES(encrypt_time),
        encrypted_size = VALUES(encrypted_size),
        entropy_ciphertext = VALUES(entropy_ciphertext),
        entropy_plaintext = VALUES(entropy_plaintext),
        decrypt_time = VALUES(decrypt_time),
        decrypted_size = VALUES(decrypted_size),
        verified = VALUES(verified),
        qr_code = VALUES(qr_code),
        total_process_time = VALUES(total_process_time),
        file_load_time = VALUES(file_load_time),
        encryption = VALUES(encryption),
        ciphertext = VALUES(ciphertext),
        decryption = VALUES(decryption),
        private_key = VALUES(private_key),
        public_key = VALUES(public_key),
        updated_at = VALUES(updated_at)";
        $stmt = $this->pdo->prepare($sql);

        // Bind parameters
        $stmt->bindParam(':filename', $data['filename']);
        $stmt->bindParam(':algorithm', $data['algorithm']);
        $stmt->bindParam(':mode', $data['mode']);
        $stmt->bindParam(':block_mode', $data['block_mode']);
        $stmt->bindParam(':stream_mode', $data['stream_mode']);
        $stmt->bindParam(':original_size', $data['original_size'], PDO::PARAM_INT);
        $stmt->bindParam(':hash', $data['hash']);
        $stmt->bindParam(':hash_time', $data['hash_time']);
        $stmt->bindParam(':message_digest', $data['message_digest']);
        $stmt->bindParam(':avalanche', $data['avalanche']);
        $stmt->bindParam(':encrypt_time', $data['encrypt_time']);
        $stmt->bindParam(':encrypted_size', $data['encrypted_size'], PDO::PARAM_INT);
        $stmt->bindParam(':entropy_ciphertext', $data['entropy_ciphertext']);
        $stmt->bindParam(':entropy_plaintext', $data['entropy_plaintext']);
        $stmt->bindParam(':decrypt_time', $data['decrypt_time']);
        $stmt->bindParam(':decrypted_size', $data['decrypted_size'], PDO::PARAM_INT);
        $stmt->bindParam(':verified', $data['verified']);
        $stmt->bindParam(':qr_code', $data['qr_code']);
        $stmt->bindParam(':total_process_time', $data['total_process_time']);
        $stmt->bindParam(':file_load_time', $data['file_load_time']);
        $stmt->bindParam(':encryption', $data['encryption']);
        $stmt->bindParam(':ciphertext', $data['ciphertext']);
        $stmt->bindParam(':decryption', $data['decryption']);
        $stmt->bindParam(':private_key', $data['private_key']);
        $stmt->bindParam(':public_key', $data['public_key']);
        $stmt->bindParam(':created_at', $data['created_at']);
        $stmt->bindParam(':updated_at', $data['updated_at']);

        try {
            $stmt->execute();
        } catch (PDOException $e) {
            echo "Error saving to database: " . $e->getMessage() . "\n";
        }
    }
    // Fungsi untuk menghitung Avalanche Effect antara dua ciphertext
    private function calculateAvalancheEffect($ciphertext1, $ciphertext2)
    {
        // Validasi: Pastikan kedua parameter adalah string
        if (!is_string($ciphertext1) || !is_string($ciphertext2)) {
            return 0; // Kembalikan 0 jika bukan string
        }

        // Inisialisasi variabel untuk menyimpan representasi biner dari masing-masing ciphertext
        $binaryCiphertext1 = '';
        $binaryCiphertext2 = '';

        // Hitung panjang maksimum dari kedua ciphertext
        $maxLength = max(strlen($ciphertext1), strlen($ciphertext2));

        // Loop untuk mengonversi setiap karakter ke biner 8-bit
        for ($i = 0; $i < $maxLength; $i++) {
            // Ambil karakter dari ciphertext1, jika kosong gunakan NULL char
            $char1 = $i < strlen($ciphertext1) ? $ciphertext1[$i] : "\0";

            // Ambil karakter dari ciphertext2, jika kosong gunakan NULL char
            $char2 = $i < strlen($ciphertext2) ? $ciphertext2[$i] : "\0";

            // Konversi karakter ke biner 8-bit dan tambahkan ke string biner
            $binaryCiphertext1 .= sprintf('%08b', ord($char1));
            $binaryCiphertext2 .= sprintf('%08b', ord($char2));
        }

        // Inisialisasi variabel untuk menghitung jumlah bit yang berbeda
        $differentBits = 0;

        // Total bit yang dibandingkan (pasti sama panjang karena disamakan di atas)
        $totalBits = strlen($binaryCiphertext1);

        // Jika tidak ada bit untuk dibandingkan, kembalikan 0
        if ($totalBits === 0) {
            return 0;
        }

        // Bandingkan tiap bit satu per satu
        for ($i = 0; $i < $totalBits; $i++) {
            // Jika bit berbeda, tambah counter differentBits
            if ($binaryCiphertext1[$i] !== $binaryCiphertext2[$i]) {
                $differentBits++;
            }
        }

        // Hitung persentase perubahan bit (Avalanche Effect)
        $avalanchePercentage = ($differentBits / $totalBits) * 100;

        // Kembalikan persentasenya
        return $avalanchePercentage;
    }


    // private function calculateAvalancheEffect($original, $encrypted)
    // {
    //     if (!is_string($original) || !is_string($encrypted)) {
    //         return 0;
    //     }

    //     $originalBin = '';
    //     $encryptedBin = '';
    //     $length = min(strlen($original), strlen($encrypted));

    //     for ($i = 0; $i < $length; $i++) {
    //         $originalBin .= sprintf('%08b', ord($original[$i]));
    //         $encryptedBin .= sprintf('%08b', ord($encrypted[$i]));
    //     }

    //     $diffBits = 0;
    //     $totalBits = strlen($encryptedBin);

    //     if ($totalBits === 0) {
    //         return 0;
    //     }

    //     for ($i = 0; $i < $totalBits; $i++) {
    //         if ($originalBin[$i] !== $encryptedBin[$i]) {
    //             $diffBits++;
    //         }
    //     }

    //     return ($diffBits / $totalBits) * 100;
    // }

    private function generateKeys($algorithm)
    {
        switch ($algorithm) {
            case 'RSA':
                $keys = RSA::createKey(4096);
                return [
                    'private_key' => $keys->toString('PKCS8'),
                    'public_key' => $keys->getPublicKey()->toString('PKCS8'),
                ];

            case 'ECDSA':
                $curve = 'secp521r1';
                $privateKey = EC::createKey($curve);
                $publicKey = $privateKey->getPublicKey();
                return [
                    'private_key' => $privateKey->toString('PKCS8'),
                    'public_key' => $publicKey->toString('PKCS8'),
                ];

            case 'ElGamal':
                $privateKey = random_bytes(32);
                $publicKey = bin2hex($privateKey);
                return [
                    'private_key' => $privateKey,
                    'public_key' => $publicKey,
                ];

            case "RSA + ECDSA":
                $keysRSA = RSA::createKey(4096);
                $curve = 'secp521r1';
                $privateKey = EC::createKey($curve);
                $publicKey = $privateKey->getPublicKey();

                return [
                    'rsa_private_key' => $keysRSA->toString('PKCS8'),
                    'rsa_public_key' => $keysRSA->getPublicKey()->toString('PKCS8'),
                    'ecdsa_private_key' => $privateKey->toString('PKCS8'),
                    'ecdsa_public_key' => $publicKey->toString('PKCS8'),
                ];
            case 'RSA + AES-128 CBC + SHA-3 Keccak':
                $rsaKeys = RSA::createKey(2408);
                $aesKey = bin2hex(random_bytes(16)); // 128-bit key
                return [
                    'rsa_private_key' => $rsaKeys->toString('PKCS8'),
                    'rsa_public_key' => $rsaKeys->getPublicKey()->toString('PKCS8'),
                    'private_key' => $aesKey,
                ];

                // RSA + SHA-256
            case 'RSA + SHA-256 + 851':
                $rsaKeys = RSA::createKey(851);
                return [
                    'rsa_private_key' => $rsaKeys->toString('PKCS8'),
                    'rsa_public_key' => $rsaKeys->getPublicKey()->toString('PKCS8'),
                ];
            case 'RSA + SHA-256 + 483':
                $rsaKeys = RSA::createKey(483);
                return [
                    'rsa_private_key' => $rsaKeys->toString('PKCS8'),
                    'rsa_public_key' => $rsaKeys->getPublicKey()->toString('PKCS8'),
                ];

                // RSA + AES-128 CBC + MD5
            case 'RSA + AES-128 CBC + MD5':
                $rsaKeys = RSA::createKey(1024);
                $aesKey = bin2hex(random_bytes(16)); // 128-bit key
                return [
                    'rsa_private_key' => $rsaKeys->toString('PKCS8'),
                    'rsa_public_key' => $rsaKeys->getPublicKey()->toString('PKCS8'),
                    'private_key' => $aesKey,
                ];
            case 'RSA + SHA-256':
                $keys = RSA::createKey(4096);
                return [
                    'private_key' => $keys->toString('PKCS8'),
                    'public_key' => $keys->getPublicKey()->toString('PKCS8'),
                ];

                // ElGamal + SHA-3
            case 'ElGamal + SHA-3':
                $privateKey = random_bytes(32);
                $publicKey = bin2hex($privateKey);
                return [
                    'private_key' => $privateKey,
                    'public_key' => $publicKey,
                ];

            case 'RSA + SHA-256':
                $rsaKeys = RSA::createKey(4096);
                return [
                    'rsa_private_key' => $rsaKeys->toString('PKCS8'),
                    'rsa_public_key' => $rsaKeys->getPublicKey()->toString('PKCS8'),
                ];

                // ECDSA + SHA-256
            case 'ECDSA + SHA-256':
                $curve = 'secp256r1';
                $privateKey = EC::createKey($curve);
                $publicKey = $privateKey->getPublicKey();
                return [
                    'private_key' => $privateKey->toString('PKCS8'),
                    'public_key' => $publicKey->toString('PKCS8'),
                ];


            case 'ECDSA + RSA':
                $keysRSA = RSA::createKey(2048);
                $curve = 'secp521r1';
                $privateKey = EC::createKey($curve);
                $publicKey = $privateKey->getPublicKey();

                return [
                    'rsa_private_key' => $keysRSA->toString('PKCS8'),
                    'rsa_public_key' => $keysRSA->getPublicKey()->toString('PKCS8'),
                    'ecdsa_private_key' => $privateKey->toString('PKCS8'),
                    'ecdsa_public_key' => $publicKey->toString('PKCS8'),
                ];

            case 'Schnorr':
                $privateKey = random_bytes(32);
                $publicKey = bin2hex($privateKey);
                return [
                    'private_key' => $privateKey,
                    'public_key' => $publicKey,
                ];

            case 'AES':
                return [
                    'private_key' => bin2hex(random_bytes(32)),
                    'public_key' => '',
                ];

            case 'DES':
                return [
                    'private_key' => bin2hex(random_bytes(32)),
                    'public_key' => '',
                ];

            case '3DES':
                return [
                    'private_key' => bin2hex(random_bytes(24)),
                    'public_key' => '',
                ];

            case 'ChaCha20':
                return [
                    'private_key' => bin2hex(random_bytes(32)),
                    'public_key' => '',
                ];

            case 'RC4':
                return [
                    'private_key' => bin2hex(random_bytes(16)),
                    'public_key' => '',
                ];

            default:
                return [
                    'private_key' => 'private_key_' . $algorithm,
                    'public_key' => 'public_key_' . $algorithm,
                ];
        }
    }

    private function encryptContent($content, $algorithm, $publicKey, $privateKey, $rsaPublicKey, $ecdsaPrivateKey, $mode, $blockMode = null, $streamMode = null)
    {
        // var_dump($privateKey);die;
        try {
            switch ($algorithm) {
                case 'RSA':
                    $rsa = PublicKeyLoader::load($publicKey);
                    $rsa = $rsa->withPadding(RSA::ENCRYPTION_OAEP);
                    return $rsa->encrypt($content);

                case 'ECDSA':
                    $ec = PublicKeyLoader::load($privateKey);
                    $ec = $ec->withHash('sha512');
                    $signature = $ec->sign($content);
                    return base64_encode($signature);

                case "RSA + ECDSA":
                    $rsa = PublicKeyLoader::load($rsaPublicKey);
                    $rsa = $rsa->withPadding(RSA::ENCRYPTION_OAEP);
                    $encryptedContent = $rsa->encrypt($content);

                    $ec = PublicKeyLoader::load($ecdsaPrivateKey);
                    $ec = $ec->withHash('sha512');
                    $signature = $ec->sign($encryptedContent);

                    return [
                        'encrypted' => $encryptedContent,
                        'signature' => $signature
                    ];
                case 'RSA + AES-128 CBC + SHA-3 Keccak':
                    $rsa = PublicKeyLoader::load($rsaPublicKey);
                    $rsa = $rsa->withPadding(RSA::ENCRYPTION_OAEP);

                    // Langkah 1: Enkripsi konten dengan RSA
                    $rsaEncryptedContent = $rsa->encrypt($content);
                    // $rsaEncryptedContent = "Haii";

                    // var_dump($rsaEncryptedContent);die;

                    // Langkah 2: Enkripsi hasil RSA menggunakan AES
                    $aes = new AES('cbc');
                    $aes->setKey(hex2bin($privateKey)); // AES key = 128 bit
                    // $aes->setKey(bin2hex(random_bytes(16))); // AES key = 128 bit
                    $iv = random_bytes(16);
                    $aes->setIV($iv);

                    $doubleEncryptedContent = $aes->encrypt($rsaEncryptedContent);

                    return [
                        'iv' => bin2hex($iv),
                        'encrypted' => base64_encode($rsaEncryptedContent),
                        'signature' => base64_encode($doubleEncryptedContent),
                    ];

                case 'RSA + AES-128 CBC + MD5':
                    $rsa = PublicKeyLoader::load($rsaPublicKey);
                    $rsa = $rsa->withPadding(RSA::ENCRYPTION_OAEP);

                    // Langkah 1: Enkripsi konten dengan RSA
                    $rsaEncryptedContent = $rsa->encrypt($content);
                    // $rsaEncryptedContent = "Haii";

                    // var_dump($rsaEncryptedContent);die;

                    // Langkah 2: Enkripsi hasil RSA menggunakan AES
                    $aes = new AES('cbc');
                    $aes->setKey(hex2bin($privateKey)); // AES key = 128 bit
                    // $aes->setKey(bin2hex(random_bytes(16))); // AES key = 128 bit
                    $iv = random_bytes(16);
                    $aes->setIV($iv);

                    $doubleEncryptedContent = $aes->encrypt($rsaEncryptedContent);

                    return [
                        'iv' => bin2hex($iv),
                        'encrypted' => base64_encode($rsaEncryptedContent),
                        'signature' => base64_encode($doubleEncryptedContent),
                    ];

                    // RSA + SHA-256

                case 'RSA + SHA-256 + 851':
                    $rsa = PublicKeyLoader::load($publicKey);
                    $rsa = $rsa->withPadding(RSA::ENCRYPTION_OAEP)
                        ->withHash('sha256');
                    return base64_encode($rsa->encrypt($content));

                case 'RSA + SHA-256':
                    $rsa = PublicKeyLoader::load($publicKey);
                    $rsa = $rsa->withPadding(RSA::ENCRYPTION_OAEP);
                    return $rsa->encrypt($content);

                    // ECDSA + SHA-256
                case 'ECDSA + SHA-256':
                    $ec = PublicKeyLoader::load($privateKey);
                    $ec = $ec->withHash('sha256');
                    $signature = $ec->sign($content);
                    return base64_encode($signature);

                    // ElGamal + SHA-3 (Mock)
                case 'ElGamal + SHA-3':
                    // Ini hanya mock untuk demonstrasi, bukan implementasi kriptografi ElGamal yang sesungguhnya.
                    return base64_encode($content . '_elgamal_sha3');

                case 'ECDSA + RSA':
                    $ec = PublicKeyLoader::load($ecdsaPrivateKey);
                    $ec = $ec->withHash('sha512');
                    $signature = $ec->sign($content);

                    $rsa = PublicKeyLoader::load($rsaPublicKey);
                    $rsa = $rsa->withPadding(RSA::ENCRYPTION_OAEP)
                        ->withHash('sha512');
                    $encrypted = $rsa->encrypt($content);

                    return [
                        'encrypted' => $encrypted,
                        'signature' => $signature
                    ];

                case 'AES':
                    $aes = new AES($mode === 'Block' ? $blockMode : $streamMode);
                    $aes->setKey(hex2bin($privateKey));
                    $iv = random_bytes(16);
                    $aes->setIV($iv);
                    $ciphertext = $aes->encrypt($content);
                    return $iv . $ciphertext;

                case 'DES':
                    $des = new DES($mode === 'Block' ? $blockMode : $streamMode);
                    $des->setKey(hex2bin($publicKey));
                    $iv = random_bytes(16);
                    $des->setIV($iv);
                    return $iv . $des->encrypt($content);

                case '3DES':
                    $des3 = new DES($mode === 'Block' ? $blockMode : $streamMode);
                    $des3->setKey(hex2bin($publicKey));
                    $iv = random_bytes(8);
                    $des3->setIV($iv);
                    return $iv . $des3->encrypt($content);

                default:
                    return "Algorithm not supported";
            }
        } catch (\Exception $e) {
            return "Error during encryption: " . $e->getMessage();
        }
    }

    private function decryptContent($content, $encryptedContent, $algorithm, $iv, $privateKey, $publicKey, $rsaPrivateKey, $ecdsaPublicKey, $encrypted, $signature, $mode, $blockMode = null, $streamMode = null)
    {
        try {
            switch ($algorithm) {
                case 'RSA':
                    $rsa = PublicKeyLoader::load($privateKey);
                    $rsa = $rsa->withPadding(RSA::ENCRYPTION_OAEP);
                    return $rsa->decrypt($encryptedContent);

                case 'ECDSA':
                    $publicKey = PublicKeyLoader::load($publicKey);
                    $publicKey = $publicKey->withHash('sha512');
                    $signature = base64_decode($encryptedContent);
                    $isValid = $publicKey->verify($content, $signature);

                    if ($isValid) {
                        return "Tanda tangan valid. Data tidak diubah.";
                    } else {
                        return "Tanda tangan tidak valid. Data mungkin diubah atau kunci tidak sesuai.";
                    }

                case "RSA + ECDSA":
                    $encryptedContent = $encrypted;
                    $signature = $signature;

                    $ec = PublicKeyLoader::load($ecdsaPublicKey);
                    $ec = $ec->withHash('sha512');
                    $isValid = $ec->verify($encrypted, $signature);

                    if (!$isValid) {
                        return "Tanda tangan tidak valid. Data mungkin telah dimodifikasi.";
                    }

                    $rsa = PublicKeyLoader::load($rsaPrivateKey);
                    $rsa = $rsa->withPadding(RSA::ENCRYPTION_OAEP);

                    try {
                        $decryptedContent = $rsa->decrypt($encryptedContent);
                        return [
                            'decrypted' => $decryptedContent,
                            'signature_valid' => true
                        ];
                    } catch (Exception $e) {
                        return "Dekripsi gagal: " . $e->getMessage();
                    }
                case 'RSA + AES-128 CBC + SHA-3 Keccak':
                    $aes = new AES('cbc');
                    $aes->setKey(hex2bin($privateKey)); // Kunci AES = sama dengan yang dipakai saat enkripsi
                    $aes->setIV(hex2bin($iv)); // IV dari hasil enkripsi
                    $rsaEncryptedContent = $aes->decrypt(base64_decode($signature));

                    // Langkah 2: Dekripsi RSA untuk mendapatkan konten asli
                    $rsa = PublicKeyLoader::load($rsaPrivateKey); // Load RSA private key
                    $rsa = $rsa->withPadding(RSA::ENCRYPTION_OAEP);
                    $originalContent = $rsa->decrypt($rsaEncryptedContent);

                    return [
                        'decrypted' => $originalContent,
                        'signature_valid' => true
                    ];
                case 'RSA + AES-128 CBC + MD5':
                    // Langkah 1: Dekripsi AES dulu
                    // $iv = substr($signature, 0, 16);
                    // $signature = substr($signature, 16);
                    $aes = new AES('cbc');
                    $aes->setKey(hex2bin($privateKey)); // Kunci AES = sama dengan yang dipakai saat enkripsi
                    $aes->setIV(hex2bin($iv)); // IV dari hasil enkripsi
                    $rsaEncryptedContent = $aes->decrypt(base64_decode($signature));

                    // Langkah 2: Dekripsi RSA untuk mendapatkan konten asli
                    $rsa = PublicKeyLoader::load($rsaPrivateKey); // Load RSA private key
                    $rsa = $rsa->withPadding(RSA::ENCRYPTION_OAEP);
                    $originalContent = $rsa->decrypt($rsaEncryptedContent);

                    return [
                        'decrypted' => $originalContent,
                        'signature_valid' => true
                    ];

                    // RSA + SHA-256
                case 'RSA + SHA-256':
                    $rsa = PublicKeyLoader::load($privateKey);
                    $rsa = $rsa->withPadding(RSA::ENCRYPTION_OAEP);
                    return $rsa->decrypt($encryptedContent);


                    // ECDSA + SHA-256
                case 'ECDSA + SHA-256':
                    $publicKey = PublicKeyLoader::load($publicKey);
                    $publicKey = $publicKey->withHash('sha256');
                    $signature = base64_decode($encrypted);

                    $isValid = $publicKey->verify($content, $signature);
                    return $isValid ? "Tanda tangan valid." : "Tanda tangan tidak valid.";

                    // ElGamal + SHA-3 (Mock)
                case 'ElGamal + SHA-3':
                    // Mock verifikasi – implementasi nyata butuh lib ElGamal yang sesungguhnya
                    return str_replace('_elgamal_sha3', '', base64_decode($encrypted));

                case 'ECDSA + RSA':
                    $encryptedContent = $encrypted;
                    $signature = $signature;

                    $ec = PublicKeyLoader::load($ecdsaPublicKey);
                    $ec = $ec->withHash('sha512');
                    $isValid = $ec->verify($content, $signature);

                    if (!$isValid) {
                        return [
                            'status' => 'error',
                            'message' => 'Tanda tangan tidak valid! Data mungkin telah dimodifikasi.'
                        ];
                    }

                    $rsa = PublicKeyLoader::load($rsaPrivateKey);
                    $rsa = $rsa->withPadding(RSA::ENCRYPTION_OAEP)
                        ->withHash('sha512');
                    $decrypted = $rsa->decrypt($encryptedContent);

                    return [
                        'status' => 'success',
                        'signature_valid' => 'Data berhasil didekripsi dan tanda tangan valid.',
                        'decrypted' => $decrypted
                    ];

                case 'AES':
                    $iv = substr($encryptedContent, 0, 16);
                    $ciphertext = substr($encryptedContent, 16);

                    $aes = new AES($mode === 'Block' ? $blockMode : $streamMode);
                    $aes->setKey(hex2bin($privateKey));
                    $aes->setIV($iv);
                    return $aes->decrypt($ciphertext);

                case 'DES':
                    $des = new DES($mode === 'Block' ? $blockMode : $streamMode);
                    $des->setKey(hex2bin($privateKey));
                    $iv = substr($encryptedContent, 0, 8);
                    $ciphertext = substr($encryptedContent, 8);
                    $des->setIV($iv);
                    return $des->decrypt($ciphertext);

                case '3DES':
                    $des3 = new DES($mode === 'Block' ? $blockMode : $streamMode);
                    $des3->setKey(hex2bin($privateKey));
                    $iv = substr($encryptedContent, 0, 8);
                    $ciphertext = substr($encryptedContent, 8);
                    $des3->setIV($iv);
                    return $des3->decrypt($ciphertext);

                default:
                    return "Algorithm not supported";
            }
        } catch (\Exception $e) {
            return "Error during decryption: " . $e->getMessage();
        }
    }

    public function calculateEntropy($string)
    {
        $length = strlen($string);
        if ($length === 0) {
            return 0.0;
        }

        $frequency = array_count_values(str_split($string));
        $entropy = 0.0;

        foreach ($frequency as $count) {
            $probability = $count / $length;
            $entropy -= $probability * log($probability, 2);
        }

        return $entropy;
    }

    public function extractElements($elements)
    {
        $text = '';
        foreach ($elements as $element) {
            if ($element instanceof \PhpOffice\PhpWord\Element\Text) {
                $text .= $element->getText() . ' ';
            } elseif ($element instanceof \PhpOffice\PhpWord\Element\TextRun) {
                foreach ($element->getElements() as $textElement) {
                    if ($textElement instanceof \PhpOffice\PhpWord\Element\Text) {
                        $text .= $textElement->getText() . ' ';
                    }
                }
            } elseif ($element instanceof \PhpOffice\PhpWord\Element\TextBreak) {
                $text .= "\n";
            } elseif ($element instanceof \PhpOffice\PhpWord\Element\Table) {
                foreach ($element->getRows() as $row) {
                    foreach ($row->getCells() as $cell) {
                        foreach ($cell->getElements() as $cellElement) {
                            if ($cellElement instanceof \PhpOffice\PhpWord\Element\Text) {
                                $text .= $cellElement->getText() . " ";
                            } elseif ($cellElement instanceof \PhpOffice\PhpWord\Element\TextRun) {
                                foreach ($cellElement->getElements() as $textElement) {
                                    if ($textElement instanceof \PhpOffice\PhpWord\Element\Text) {
                                        $text .= $textElement->getText() . " ";
                                    }
                                }
                            }
                        }
                    }
                    $text .= "\n";
                }
            }
        }
        return $text;
    }

    // ... [Keep all the other methods unchanged from the previous version] ...
}

// Example usage with MySQL connection:
$dbHost = 'localhost';
$dbName = 'kriptografi';
$dbUser = 'root';
$dbPass = 'root';

try {
    $signer = new FileSigner($dbHost, $dbName, $dbUser, $dbPass);
    $results = $signer->processFolder(
        '../experimen_skripsi2',
        'RSA + SHA-256',
        'Hash',
        'sha256',
        'cbc'
    );

    print_r($results);

    // Optionally save results to CSV
    if (!empty($results)) {
        $csvFile = fopen('signature_results.csv', 'w');
        fputcsv($csvFile, array_keys($results[0]));
        foreach ($results as $row) {
            fputcsv($csvFile, $row);
        }
        fclose($csvFile);
    }
} catch (GlobalException $e) {
    echo "Error: " . $e->getMessage();
}
