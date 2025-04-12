// import fs from "fs";
// import path from "path";
// import { faker } from "@faker-js/faker";

const fs = require("fs");
const path = require("path");
const { faker } = require("@faker-js/faker");

const outputDir = "experimen_skripsi4";
if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir);
}

// Ukuran file yang akan dibuat (dalam MB)
const fileSizes = [
    // ...Array.from({ length:10 }, (_, i) => (i + 1)), // 1MB - 10MB
    // ...Array.from({ length: 100 }, (_, i) => (i + 1) * 0.1), // 10MB - 100MB
    // ...Array.from({ length: 4 }, (_, i) => (i + 1) * 100) // 100MB - 400MB
    // File 1–10: 1MB sampai 10MB
  ...Array.from({ length: 10 }, (_, i) => (i + 1)),

  // File 11–100: dari 10MB ke 1024MB dalam 90 langkah, dibulatkan
  ...Array.from({ length: 90 }, (_, i) =>
    Math.round(10 + (i + 1) * ((1024 - 10) / 40))
  )
];

function generateFakeData() {
    return `Name: ${faker.person.fullName()}\n`
        + `Address: ${faker.location.streetAddress()}, ${faker.location.city()}, ${faker.location.country()}\n`
        + `Phone: ${faker.phone.number()}\n`
        + `Email: ${faker.internet.email()}\n\n`;
}

async function createFile(sizeMB) {
    return new Promise((resolve, reject) => {
        const fileSize = sizeMB * 1024 * 1024; // Konversi ke byte
        const filePath = path.join(outputDir, `file_${sizeMB}MB.txt`);
        const stream = fs.createWriteStream(filePath, { encoding: "utf-8" });

        let writtenBytes = 0;

        function writeData() {
            let ok = true;
            while (writtenBytes < fileSize && ok) {
                const chunk = generateFakeData();
                const chunkSize = Buffer.byteLength(chunk, "utf-8");

                if (writtenBytes + chunkSize > fileSize) {
                    const remainingSize = fileSize - writtenBytes;
                    ok = stream.write(chunk.substring(0, remainingSize));
                    writtenBytes += remainingSize;
                } else {
                    ok = stream.write(chunk);
                    writtenBytes += chunkSize;
                }
            }

            if (writtenBytes >= fileSize) {
                stream.end(() => {
                    console.log(`✅ File berhasil dibuat: ${filePath} (${sizeMB} MB)`);
                    resolve();
                });
            } else {
                stream.once("drain", writeData);
            }
        }

        writeData();
    });
}

async function generateFiles() {
    for (const size of fileSizes) {
        await createFile(size);
    }
    console.log("🎉 Semua file selesai dibuat!");
}

generateFiles();
