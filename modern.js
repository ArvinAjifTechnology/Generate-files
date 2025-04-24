const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const mysql = require("mysql2/promise");

// Konfigurasi Database
const dbConfig = {
  host: "localhost",
  user: "root",
  password: "root",
  database: "kriptografi",
  connectionLimit: 10,
};
// console.log(crypto.getCurves());
// Buat koneksi pool
const pool = mysql.createPool(dbConfig);

// ========== ENCRYPTION/DECRYPTION FUNCTIONS ==========
// AES Encryption
async function encryptAES(data, key, iv, mode = "cbc") {
  const cipher = crypto.createCipheriv(
    `aes-256-${mode.toLowerCase()}`,
    key.key,
    key.iv
  );
  const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
  return { ciphertext: encrypted };
}

// AES Decryption
async function decryptAES(encryptedData, key, iv, mode = "cbc") {
  const decipher = crypto.createDecipheriv(
    `aes-256-${mode.toLowerCase()}`,
    key.key,
    key.iv
  );
  return Buffer.concat([
    decipher.update(encryptedData.ciphertext),
    decipher.final(),
  ]);
}
async function encrypt3DES(data, keyStr, ivStr) {
  if (
    !data ||
    (typeof data !== "string" && !Buffer.isBuffer(data) && !data?.ciphertext)
  ) {
    throw new Error("Data untuk enkripsi 3DES tidak valid");
  }

  if (!keyStr || !ivStr) {
    throw new Error("Key dan IV tidak boleh undefined pada encrypt3DES");
  }

  const key = Buffer.isBuffer(keyStr) ? keyStr : Buffer.from(keyStr, "utf8");
  const iv = Buffer.isBuffer(ivStr) ? ivStr : Buffer.from(ivStr, "utf8");

  if (key.length !== 24) {
    throw new Error("Key 3DES harus 24 byte");
  }

  if (iv.length !== 8) {
    throw new Error("IV untuk 3DES harus 8 byte");
  }

  const dataBuffer = Buffer.isBuffer(data)
    ? data
    : typeof data === "string"
    ? Buffer.from(data, "utf8")
    : data?.ciphertext instanceof Buffer
    ? data.ciphertext
    : Buffer.from(data);

  const cipher = crypto.createCipheriv("des-ede3-cbc", key, iv);
  const encrypted = Buffer.concat([cipher.update(dataBuffer), cipher.final()]);
  return { ciphertext: encrypted };
}

async function decrypt3DES(encryptedData, key, iv) {
  const decipher = crypto.createDecipheriv("des-ede3-cbc", key, iv);
  return Buffer.concat([
    decipher.update(encryptedData.ciphertext),
    decipher.final(),
  ]);
}

// ECC Encryption
async function encryptECC(data, publicKey) {
  // Create ECDH instance and generate keys
  const ecdh = crypto.createECDH("secp521r1");
  const ecdhPrivateKey = ecdh.generateKeys();
  const ecdhPublicKey = ecdh.getPublicKey();

  // Derive shared secret
  const sharedSecret = ecdh.computeSecret(publicKey, "base64");

  // Use the shared secret to create an AES key
  const derivedKey = crypto.createHash("sha256").update(sharedSecret).digest();
  const iv = crypto.randomBytes(16);

  // Encrypt the data with AES
  const cipher = crypto.createCipheriv("aes-256-cbc", derivedKey, iv);
  const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);

  return {
    ciphertext: encrypted,
    publicKey: ecdhPublicKey,
    iv: iv,
  };
}

// ECC Decryption
async function decryptECC(encryptedData, privateKey) {
  // Create ECDH instance with our private key
  const ecdh = crypto.createECDH("secp521r1");
  ecdh.setPrivateKey(privateKey, "base64");

  // Derive shared secret
  const sharedSecret = ecdh.computeSecret(encryptedData.publicKey, "base64");

  // Use the shared secret to create an AES key
  const derivedKey = crypto.createHash("sha256").update(sharedSecret).digest();

  // Decrypt the data with AES
  const decipher = crypto.createDecipheriv(
    "aes-256-cbc",
    derivedKey,
    encryptedData.iv
  );
  return Buffer.concat([
    decipher.update(encryptedData.ciphertext),
    decipher.final(),
  ]);
}

// AES + 3DES Encryption (two-step)
async function encryptAES3DES(data, aesKey, aesIv, desKey, desIv, mode = "cbc") {
  // Validate inputs
  if (!aesKey || !aesIv || !desKey || !desIv) {
    throw new Error("All keys and IVs must be provided for AES+3DES encryption");
  }

  // Step 1: AES Encryption
  const aesCipher = crypto.createCipheriv(
    `aes-256-${mode.toLowerCase()}`,
    aesKey,
    aesIv
  );
  const aesEncrypted = Buffer.concat([
    aesCipher.update(data),
    aesCipher.final(),
  ]);

  // Step 2: 3DES Encryption
  const desCipher = crypto.createCipheriv("des-ede3-cbc", desKey, desIv);
  const doubleEncrypted = Buffer.concat([
    desCipher.update(aesEncrypted),
    desCipher.final(),
  ]);

  return {
    ciphertext: doubleEncrypted,
    aesIv: aesIv,
    desIv: desIv,
  };
}

// AES + 3DES Decryption (reverse order)
async function decryptAES3DES(encryptedData, aesKey, desKey, aesIv, desIv, mode = "cbc") {
  // Validate inputs
  if (!aesKey || !aesIv || !desKey || !desIv) {
    throw new Error("All keys and IVs must be provided for AES+3DES decryption");
  }

  // Step 1: 3DES Decryption
  const desDecipher = crypto.createDecipheriv("des-ede3-cbc", desKey, desIv);
  const aesEncrypted = Buffer.concat([
    desDecipher.update(encryptedData.ciphertext),
    desDecipher.final(),
  ]);

  // Step 2: AES Decryption
  const aesDecipher = crypto.createDecipheriv(
    `aes-256-${mode.toLowerCase()}`,
    aesKey,
    aesIv
  );
  return Buffer.concat([aesDecipher.update(aesEncrypted), aesDecipher.final()]);
}
// Hybrid AES+ECC Encryption
async function encryptHybridAESECC(data, keys, mode = "cbc") {
  // Enkripsi data dengan AES terlebih dahulu
  const aesEncrypted = await encryptAES(
    data,
    { key: keys.aesKey, iv: keys.aesIv },
    mode
  );

  // Enkripsi kunci AES dengan ECC
  const encryptedKey = await encryptECC(keys.aesKey, keys.eccPublicKey);

  return {
    ciphertext: aesEncrypted.ciphertext,
    encryptedKey: encryptedKey.ciphertext,
    eccPublicKey: encryptedKey.publicKey,
    iv: keys.aesIv,
    eccIv: encryptedKey.iv,
  };
}

// Hybrid AES+ECC Decryption
async function decryptHybridAESECC(encryptedData, keys) {
  // Dekripsi kunci AES dengan ECC terlebih dahulu
  const aesKey = await decryptECC(
    {
      ciphertext: encryptedData.encryptedKey,
      publicKey: encryptedData.eccPublicKey,
      iv: encryptedData.eccIv,
    },
    keys.eccPrivateKey
  );

  // Dekripsi data dengan AES
  return await decryptAES(
    { ciphertext: encryptedData.ciphertext },
    { key: aesKey, iv: encryptedData.iv },
    "cbc"
  );
}

// ========== DATABASE FUNCTIONS ==========
async function verifyDatabaseSchema() {
  const connection = await pool.getConnection();
  try {
    await connection.query(`
      CREATE TABLE IF NOT EXISTS modern_cryptography (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        filename VARCHAR(255) NOT NULL,
        algorithm VARCHAR(50) NOT NULL,
        mode VARCHAR(50),
        block_mode VARCHAR(50),
        original_size BIGINT NOT NULL,
        encrypt_time DOUBLE NOT NULL,
        encrypted_size BIGINT NOT NULL,
        decrypt_time DOUBLE NOT NULL,
        entropy_ciphertext DOUBLE NOT NULL,
        entropy_plaintext DOUBLE NOT NULL,
        avalanche_effect DOUBLE NOT NULL,
        verified VARCHAR(10) NOT NULL,
        total_process_time DOUBLE NOT NULL,
        ciphertext_path VARCHAR(255),
        decrypted_path VARCHAR(255),
        encryption_key BLOB,
        iv BLOB,
        public_key TEXT,
        private_key TEXT,
        aes_key BLOB,
        aes_iv BLOB,
        ecc_public_key TEXT,
        ecc_private_key TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    `);
    console.log("Tabel database sudah diverifikasi/dibuat");
  } catch (error) {
    console.error("Gagal memverifikasi skema database:", error);
    throw error;
  } finally {
    connection.release();
  }
}

// ========== MAIN PROCESSING FUNCTIONS ==========
async function processFilesFromFolder(
  folderPath,
  algorithm,
  mode,
  blockMode = null
) {
  try {
    // Buat folder jika belum ada
    if (!fs.existsSync(folderPath)) {
      fs.mkdirSync(folderPath, { recursive: true });
      console.log(`Folder baru dibuat: ${folderPath}`);
    }

    // Create modern_cryptography directory if it doesn't exist
    const modernCryptoDir = "./modern_cryptography";
    if (!fs.existsSync(modernCryptoDir)) {
      fs.mkdirSync(modernCryptoDir, { recursive: true });
      console.log(`Folder modern_cryptography dibuat`);
    }

    const algorithmFolder = path.join(
      modernCryptoDir,
      `encrypted_${algorithm.toLowerCase()}`
    );
    const decryptedFolder = path.join(
      modernCryptoDir,
      `decrypted_${algorithm.toLowerCase()}`
    );

    if (!fs.existsSync(algorithmFolder))
      fs.mkdirSync(algorithmFolder, { recursive: true });
    if (!fs.existsSync(decryptedFolder))
      fs.mkdirSync(decryptedFolder, { recursive: true });

    // Ambil semua file dan urutkan berdasarkan ukuran dari kecil ke besar
    const files = fs
      .readdirSync(folderPath)
      .map((file) => {
        const fullPath = path.join(folderPath, file);
        const stats = fs.statSync(fullPath);
        return { file, size: stats.size, isFile: stats.isFile() };
      })
      .filter((f) => f.isFile)
      .sort((a, b) => a.size - b.size) // urutan dari kecil ke besar
      .map((f) => f.file);

    const results = [];

    for (const file of files) {
      const filePath = path.join(folderPath, file);
      console.log(`Memproses file: ${file}`);
      const result = await processSingleFile(
        filePath,
        algorithm,
        mode,
        blockMode,
        algorithmFolder,
        decryptedFolder
      );
      results.push(result);
      await storeResultInDatabase(result);
    }

    return results;
  } catch (error) {
    console.error("Error saat memproses file:", error);
    throw error;
  }
}
async function processSingleFile(
  filePath,
  algorithm,
  mode,
  blockMode,
  algorithmFolder,
  decryptedFolder
) {
  const startTime = Date.now();
  const filename = path.basename(filePath);
  const content = await fs.promises.readFile(filePath);
  const originalSize = content.length;
  const keys = generateEncryptionKey(algorithm, blockMode);

  // Enkripsi
  const encryptStart = Date.now();
  const encrypted = await encryptData(
    content,
    algorithm,
    keys,
    keys.iv,
    mode,
    blockMode
  );
  const encryptTime = Date.now() - encryptStart;

  const ciphertextPath = path.join(algorithmFolder, `${filename}.enc`);
  await fs.promises.writeFile(ciphertextPath, encrypted.ciphertext);

  // Dekripsi
  const decryptStart = Date.now();
  const decrypted = await decryptData(
    encrypted,
    algorithm,
    keys,
    keys.iv,
    mode,
    blockMode
  );
  const decryptTime = Date.now() - decryptStart;

  const decryptedPath = path.join(decryptedFolder, filename);
  await fs.promises.writeFile(decryptedPath, decrypted);

  // Hitung metrik
  const sampleSize = Math.min(1024, content.length);
  const sample = content.slice(0, sampleSize);
  const encryptedSample = encrypted.ciphertext.slice(0, sampleSize);

  const entropyPlaintext = calculateEntropy(sample);
  const entropyCiphertext = calculateEntropy(encryptedSample);

  const modifiedSample = Buffer.from(sample);
  modifiedSample[0] = modifiedSample[0] ^ 1;
  const encryptedModified = await encryptData(
    modifiedSample,
    algorithm,
    keys,
    keys.iv,
    mode,
    blockMode
  );
  const avalancheEffect = calculateAvalancheEffect(
    encryptedSample,
    encryptedModified.ciphertext.slice(0, sampleSize)
  );

const result = {
  filename,
  algorithm,
  mode,
  block_mode: blockMode,
  original_size: originalSize,
  encrypt_time: (encryptTime / 1000).toFixed(8), // dalam detik
  encrypted_size: encrypted.ciphertext.length,
  decrypt_time: (decryptTime / 1000).toFixed(8), // dalam detik
  entropy_ciphertext: entropyCiphertext,
  entropy_plaintext: entropyPlaintext,
  avalanche_effect: avalancheEffect,
  verified: Buffer.compare(decrypted, content) === 0 ? "Valid" : "Invalid",
  total_process_time: ((Date.now() - startTime) / 1000).toFixed(8), // dalam detik
  ciphertext_path: ciphertextPath,
  decrypted_path: decryptedPath,
  encryption_key: keys.key || null,
  iv: keys.iv || null,
  public_key: keys.publicKey || null,
  private_key: keys.privateKey || null,
  aes_key: keys.aesKey || null,
  aes_iv: keys.aesIv || null,
  ecc_public_key: keys.eccPublicKey || null,
  ecc_private_key: keys.eccPrivateKey || null,
};


  return result;
}

// ========== HELPER FUNCTIONS ==========
function generateEncryptionKey(algorithm, blockMode) {
  switch (algorithm.toUpperCase()) {
    case "AES":
      return {
        key: crypto.randomBytes(32),
        iv: blockMode ? crypto.randomBytes(16) : null,
        type: "symmetric",
      };

    case "ECC":
      const ecdh = crypto.createECDH("secp521r1");
      const publicKey = ecdh.generateKeys("base64");
      const privateKey = ecdh.getPrivateKey("base64");
      return {
        publicKey,
        privateKey,
        type: "asymmetric",
      };

    case "3DES":
      return {
        key: crypto.randomBytes(24), // 3DES = 192 bit (24 byte)
        iv: crypto.randomBytes(8), // IV untuk 3DES biasanya 8 byte
        type: "symmetric",
      };

    case "AES+3DES":
      return {
        aesKey: crypto.randomBytes(32), // 256-bit AES key
        aesIv: crypto.randomBytes(16), // 128-bit AES IV
        desKey: crypto.randomBytes(24), // 192-bit 3DES key
        desIv: crypto.randomBytes(8), // 64-bit 3DES IV
        type: "hybrid",
      };
    case "AES+ECC":
      const hybridAesKey = crypto.randomBytes(32); // AES-256
      const hybridAesIv = blockMode ? crypto.randomBytes(16) : null;

      const { publicKey: eccPubKey, privateKey: eccPrivKey } =
        crypto.generateKeyPairSync("ec", {
          namedCurve: "secp521r1",
          publicKeyEncoding: { type: "spki", format: "pem" },
          privateKeyEncoding: { type: "pkcs8", format: "pem" },
        });

      return {
        aesKey: hybridAesKey,
        aesIv: hybridAesIv,
        eccPublicKey: eccPubKey,
        eccPrivateKey: eccPrivKey,
        type: "hybrid",
      };

    default:
      throw new Error(`Algoritma tidak didukung: ${algorithm}`);
  }
}

async function encryptData(data, algorithm, key, iv, mode, blockMode) {
  try {
    // const encryptedAES = await encryptAES(data, { key: aesKey, iv: aesIv });
    // const encrypted3DES = await encrypt3DES(encryptedAES, desKey, desIv);
    switch (algorithm.toUpperCase()) {
      case "AES":
        return await encryptAES(data, key, iv, blockMode || "cbc");
      case "ECC":
        return await encryptECC(data, key.publicKey);
      case "3DES":
        console.log("3DES Key:", key.key);
        console.log("3DES IV:", key.iv);
        return await encrypt3DES(data, key.key, key.iv);

      case "AES+3DES":
        return await encryptAES3DES(
          data,
          key.aesKey,
          key.aesIv,
          key.desKey,
          key.desIv,
          blockMode || "cbc"
        );
        return await encrypt3DES(encryptedAES, key.desKey, key.desIv);

      case "AES+ECC":
        return await encryptHybridAESECC(data, key, blockMode || "cbc");
      default:
        throw new Error(`Algoritma enkripsi tidak didukung: ${algorithm}`);
    }
  } catch (error) {
    console.error("Gagal enkripsi:", error);
    throw error;
  }
}

async function decryptData(encryptedData, algorithm, key, iv, mode, blockMode) {
  try {
    switch (algorithm.toUpperCase()) {
      case "AES":
        return await decryptAES(encryptedData, key, iv, blockMode || "cbc");
      case "ECC":
        return await decryptECC(encryptedData, key.privateKey);

      case "3DES":
        return await decrypt3DES(encryptedData, key.key, key.iv);

      case "AES+3DES":
        return await decryptAES3DES(
          encryptedData,
          key.aesKey,
          key.desKey,
          key.aesIv,
          key.desIv,
          blockMode || "cbc"
        );
      case "AES+ECC":
        return await decryptHybridAESECC(data, key, blockMode || "cbc");
      default:
        throw new Error(`Algoritma dekripsi tidak didukung: ${algorithm}`);
    }
  } catch (error) {
    console.error("Gagal dekripsi:", error);
    throw error;
  }
}

function calculateEntropy(data) {
  const len = data.length;
  const freq = {};

  for (const byte of data) {
    freq[byte] = (freq[byte] || 0) + 1;
  }

  return Object.values(freq).reduce((sum, count) => {
    const p = count / len;
    return sum - p * Math.log2(p);
  }, 0);
}

function calculateAvalancheEffect(data1, data2) {
  const length = Math.min(data1.length, data2.length);
  let diffBits = 0;

  for (let i = 0; i < length; i++) {
    const byte1 = data1[i];
    const byte2 = data2[i];
    let xor = byte1 ^ byte2;

    while (xor > 0) {
      diffBits += xor & 1;
      xor >>= 1;
    }
  }

  const totalBits = length * 8;
  return totalBits > 0 ? (diffBits / totalBits) * 100 : 0;
}

async function storeResultInDatabase(result) {
  const connection = await pool.getConnection();
  try {
    await connection.query(`INSERT INTO modern_cryptography SET ?`, [result]);
  } catch (error) {
    console.error("Error database:", error);
    throw error;
  } finally {
    connection.release();
  }
}

// ========== MAIN EXECUTION ==========
(async () => {
  try {
    await verifyDatabaseSchema();
    const results = await processFilesFromFolder(
      "./large_files2",
      "AES+3DES",
      "CBC",
      "CBC"
    );
    console.log(`Proses selesai. Total file diproses: ${results.length}`);
  } catch (error) {
    console.error("Error fatal:", error);
    process.exit(1);
  } finally {
    await pool.end();
    process.exit(0);
  }
})();
