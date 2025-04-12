<?php
// Konfigurasi
$inputFolder = '../experimen_skripsi2'; // Folder sumber file
$outputFolder = './hash_sha512'; // Folder tujuan hasil hash
$hashAlgorithm = 'sha512'; // Algoritma hash yang digunakan

// Buat folder output jika belum ada
if (!file_exists($outputFolder)) {
    mkdir($outputFolder, 0777, true);
    echo "Folder output '$outputFolder' berhasil dibuat.\n";
}

// Baca semua file dalam folder input
$files = scandir($inputFolder);

if (count($files) <= 2) { // . dan .. dihitung
    echo "Tidak ada file dalam folder '$inputFolder'.\n";
    exit;
}

echo "Memproses " . (count($files) - 2) . " file...\n";

// Proses setiap file
foreach ($files as $file) {
    $inputFilePath = $inputFolder . '/' . $file;

    // Hanya proses file (bukan folder atau . / ..)
    if (is_file($inputFilePath)) {
        try {
            // Hitung hash file
            $fileHash = hash_file($hashAlgorithm, $inputFilePath);

            // Dapatkan ekstensi dan nama file
            $ext = pathinfo($file, PATHINFO_EXTENSION);
            $basename = pathinfo($file, PATHINFO_FILENAME);

            // Buat nama file baru
            if (!empty($ext)) {
                $newFileName = "hash_{$hashAlgorithm}_{$basename}.{$ext}";
            } else {
                $newFileName = "hash_{$hashAlgorithm}_{$basename}";
            }

            $outputFilePath = $outputFolder . '/' . $newFileName;

            // Tulis hash ke file output
            file_put_contents($outputFilePath, $fileHash);

            echo "Berhasil: $file -> $newFileName (berisi hash)\n";
        } catch (Exception $err) {
            echo "Gagal memproses file $file: " . $err->getMessage() . "\n";
        }
    }
}

echo "Proses selesai!\n";
echo "File hasil hash disimpan di folder '$outputFolder'\n";
