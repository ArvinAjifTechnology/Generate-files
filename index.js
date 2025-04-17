const fs = require("fs");
const path = require("path");

const outputDir = "experimen_kriptografi";
if (!fs.existsSync(outputDir)) {
  fs.mkdirSync(outputDir);
}

// Ukuran file dalam MB (1MB = 1024*1024 bytes)
// Ukuran file yang akan dibuat (dalam MB) - dari 1MB sampai 50MB
const fileSizes = [
  // File 1–10: 1MB sampai 10MB
  ...Array.from({ length: 10 }, (_, i) => i + 1),

  // File 11–50: dari 11MB ke 50MB dalam 40 langkah (dibulatkan, tanpa duplikasi)
  ...Array.from({ length: 40 }, (_, i) =>
    Math.round(10 + ((i + 1) * (40 / 40))) // (50 - 10) / 40 = 1 per step
  ).filter((v, i, arr) => arr.indexOf(v) === i) // hilangkan duplikat
];


// Teks yang akan diulang (panjang per baris harus dihitung presisi)
const lineText = `
Judul: Pengaruh Ukuran File terhadap Waktu Enkripsi dan Dekripsi

Abstrak:
Penelitian ini membahas dampak ukuran file terhadap efisiensi proses enkripsi dan dekripsi data. Dalam era digital saat ini, keamanan informasi menjadi krusial, terutama saat data harus dikirimkan melalui jaringan terbuka. Proses enkripsi bertujuan untuk menjaga kerahasiaan, sedangkan dekripsi memastikan data dapat dibaca kembali oleh pihak yang berwenang.

Pendahuluan:
Ukuran file memiliki pengaruh signifikan terhadap waktu yang dibutuhkan dalam proses kriptografi. Semakin besar file, semakin besar pula beban komputasi yang harus ditangani oleh algoritma enkripsi. Hal ini penting untuk dipertimbangkan dalam implementasi sistem keamanan data yang melibatkan file besar, seperti dokumen arsip, citra digital, atau video.

Metode:
Eksperimen dilakukan dengan membuat file teks berukuran 1MB hingga 1024MB, lalu dilakukan proses enkripsi dan dekripsi menggunakan algoritma tertentu seperti AES, 3DES, dan RSA. Pengukuran waktu dilakukan untuk mengevaluasi performa masing-masing algoritma terhadap berbagai ukuran file.

Hasil dan Pembahasan:
Hasil menunjukkan bahwa waktu enkripsi dan dekripsi meningkat secara linear terhadap ukuran file. Algoritma simetris seperti AES lebih cepat dibandingkan algoritma asimetris seperti RSA. Hal ini menegaskan pentingnya pemilihan algoritma berdasarkan konteks penggunaan.

Kesimpulan:
Ukuran file merupakan faktor penting dalam desain sistem kriptografi. Pemilihan algoritma dan manajemen ukuran file dapat membantu meningkatkan efisiensi sistem dan mempercepat proses transmisi data secara aman.

Kata Kunci: ukuran file, enkripsi, dekripsi, performa algoritma, keamanan data
\n`;

const lineSize = Buffer.byteLength(lineText, "utf-8"); // hitung ukuran 1 baris

async function createFile(sizeMB) {
  return new Promise((resolve, reject) => {
    const fileSizeBytes = sizeMB * 1024 * 1024;
    const filePath = path.join(outputDir, `file_${sizeMB}MB.txt`);
    const stream = fs.createWriteStream(filePath, { encoding: "utf-8" });

    let writtenBytes = 0;

    function write() {
      let ok = true;

      while (writtenBytes < fileSizeBytes && ok) {
        let remaining = fileSizeBytes - writtenBytes;

        // jika tersisa lebih kecil dari 1 baris
        if (remaining < lineSize) {
          const partialLine = lineText.substring(0, remaining);
          ok = stream.write(partialLine);
          writtenBytes += Buffer.byteLength(partialLine, "utf-8");
        } else {
          ok = stream.write(lineText);
          writtenBytes += lineSize;
        }
      }

      if (writtenBytes >= fileSizeBytes) {
        stream.end(() => {
          console.log(`✅ File berhasil dibuat: ${filePath} (${sizeMB} MB)`);
          resolve();
        });
      } else {
        stream.once("drain", write);
      }
    }

    write();
  });
}

async function generateFiles() {
  for (const size of fileSizes) {
    await createFile(size);
  }
  console.log("🎉 Semua file selesai dibuat dengan ukuran presisi!");
}

generateFiles();
