const fs = require('fs');
const path = require('path');

// Ubah 1 bit pertama dari buffer
function flipFirstBit(buffer) {
    if (buffer.length === 0) return buffer;

    const flipped = Buffer.from(buffer);
    flipped[0] ^= 0b00000001; // XOR bit pertama (bit paling kanan)
    return flipped;
}

// Folder input dan output
const inputFolder = './experimen_skripsi3';
const outputFolder = './different_experimen_skripsi3';

// Pastikan folder output ada
if (!fs.existsSync(outputFolder)) {
    fs.mkdirSync(outputFolder);
}

// Proses setiap file
fs.readdirSync(inputFolder).forEach(file => {
    const inputPath = path.join(inputFolder, file);
    const outputPath = path.join(outputFolder, file);

    if (path.extname(file) === '.txt') {
        const data = fs.readFileSync(inputPath);
        const modifiedData = flipFirstBit(data);
        fs.writeFileSync(outputPath, modifiedData);
        console.log(`Bit pertama diubah: ${file}`);
    }
});
