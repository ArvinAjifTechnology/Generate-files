// const fs = require('fs');
// const path = require('path');
// const crypto = require('crypto');

// // Konfigurasi
// const inputFolder = './experimen_skripsi2'; // Folder sumber file
// const outputFolder = './shake128'; // Folder tujuan hasil hash
// const hashAlgorithm = 'shake128'; // Algoritma hash yang digunakan

// // Fungsi untuk menghitung hash file
// async function calculateFileHash(filePath) {
//   return new Promise((resolve, reject) => {
//     const hash = crypto.createHash(hashAlgorithm);
//     const stream = fs.createReadStream(filePath);

//     stream.on('data', (data) => hash.update(data));
//     stream.on('end', () => resolve(hash.digest('hex')));
//     stream.on('error', (err) => reject(err));
//   });
// }

// // Fungsi utama untuk memproses semua file
// async function processFiles() {
//   try {
//     // Buat folder output jika belum ada
//     if (!fs.existsSync(outputFolder)) {
//       fs.mkdirSync(outputFolder, { recursive: true });
//       console.log(`Folder output '${outputFolder}' berhasil dibuat.`);
//     }

//     // Baca semua file dalam folder input
//     const files = fs.readdirSync(inputFolder);

//     if (files.length === 0) {
//       console.log(`Tidak ada file dalam folder '${inputFolder}'.`);
//       return;
//     }

//     console.log(`Memproses ${files.length} file...`);

//     // Proses setiap file
//     for (const file of files) {
//       const inputFilePath = path.join(inputFolder, file);
//       const stats = fs.statSync(inputFilePath);

//       // Hanya proses file (bukan folder)
//       if (stats.isFile()) {
//         try {
//           // Hitung hash file
//           const fileHash = await calculateFileHash(inputFilePath);
          
//           // Dapatkan ekstensi dan nama file
//           const ext = path.extname(file);
//           const basename = path.basename(file, ext);
          
//           // Buat nama file baru dengan format hash_sha512_namaaslifile.ext
//           const newFileName = `hash_${hashAlgorithm}_${basename}${ext}`;
//           const outputFilePath = path.join(outputFolder, newFileName);
          
//           // Tulis hash ke file output (bukan menyalin file asli)
//           fs.writeFileSync(outputFilePath, fileHash);
          
//           console.log(`Berhasil: ${file} -> ${newFileName} (berisi hash)`);
//         } catch (err) {
//           console.error(`Gagal memproses file ${file}:`, err.message);
//         }
//       }
//     }

//     console.log('Proses selesai!');
//     console.log(`File hasil hash disimpan di folder '${outputFolder}'`);
//   } catch (err) {
//     console.error('Terjadi kesalahan:', err);
//   }
// }

// // Jalankan aplikasi
// processFiles();

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

// Konfigurasi
const inputFolder = "./experimen_skripsi4"; // Folder sumber file
const outputFolder = "./shake128"; // Folder tujuan hasil hash
const hashAlgorithm = "shake128"; // Algoritma hash yang digunakan
const digestLength = 16; // Panjang digest dalam byte (128 bit = 16 byte)

// Fungsi untuk menghitung hash file
async function calculateFileHash(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash(hashAlgorithm);
    const stream = fs.createReadStream(filePath);

    stream.on("data", (data) => hash.update(data));
    stream.on("end", () => resolve(hash.digest("hex", digestLength)));
    stream.on("error", (err) => reject(err));
  });
}

// Fungsi utama untuk memproses semua file
async function processFiles() {
  try {
    // Buat folder output jika belum ada
    if (!fs.existsSync(outputFolder)) {
      fs.mkdirSync(outputFolder, { recursive: true });
      console.log(`Folder output '${outputFolder}' berhasil dibuat.`);
    }

    // Baca semua file dalam folder input dan dapatkan informasi ukuran
    const files = fs.readdirSync(inputFolder).map((file) => {
      const filePath = path.join(inputFolder, file);
      const stats = fs.statSync(filePath);
      return {
        name: file,
        path: filePath,
        size: stats.size,
        isFile: stats.isFile(),
      };
    });

    // Filter hanya file (bukan folder) dan urutkan berdasarkan ukuran (kecil ke besar)
    const sortedFiles = files
      .filter((file) => file.isFile)
      .sort((a, b) => a.size - b.size);

    if (sortedFiles.length === 0) {
      console.log(`Tidak ada file dalam folder '${inputFolder}'.`);
      return;
    }

    console.log(
      `Memproses ${sortedFiles.length} file (diurutkan dari yang terkecil)...`
    );

    // Proses setiap file secara berurutan
    for (const file of sortedFiles) {
      try {
        // Hitung hash file
        const fileHash = await calculateFileHash(file.path);

        // Dapatkan ekstensi dan nama file
        const ext = path.extname(file.name);
        const basename = path.basename(file.name, ext);

        // Buat nama file baru dengan format hash_sha3_namaaslifile.ext
        const newFileName = `hash_${hashAlgorithm}_${basename}${ext}`;
        const outputFilePath = path.join(outputFolder, newFileName);

        // Tulis hash ke file output (bukan menyalin file asli)
        fs.writeFileSync(outputFilePath, fileHash);

        console.log(
          `Berhasil: ${file.name} (${file.size} bytes) -> ${newFileName} (berisi hash)`
        );
      } catch (err) {
        console.error(`Gagal memproses file ${file.name}:`, err.message);
      }
    }

    console.log("Proses selesai!");
    console.log(`File hasil hash disimpan di folder '${outputFolder}'`);
  } catch (err) {
    console.error("Terjadi kesalahan:", err);
  }
}

// Jalankan aplikasi
processFiles();