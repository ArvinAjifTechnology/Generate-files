const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const mysql = require("mysql2/promise");

// Database Configuration
const dbConfig = {
  host: "localhost",
  user: "root",
  password: "root",
  database: "kriptografi",
  connectionLimit: 10,
};

// Create connection pool
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

// ECC Encryption
async function encryptECC(data, publicKey) {
  const ecdh = crypto.createECDH("c2pnb163v3");
  const ecdhPrivateKey = ecdh.generateKeys();
  const ecdhPublicKey = ecdh.getPublicKey();

  const sharedSecret = ecdh.computeSecret(publicKey, "base64");
  const derivedKey = crypto.createHash("sha256").update(sharedSecret).digest();
  const iv = crypto.randomBytes(16);

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
  const ecdh = crypto.createECDH("c2pnb163v3");
  ecdh.setPrivateKey(privateKey, "base64");

  const sharedSecret = ecdh.computeSecret(encryptedData.publicKey, "base64");
  const derivedKey = crypto.createHash("sha256").update(sharedSecret).digest();

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

// Hybrid AES+ECC Encryption
async function encryptHybridAESECC(data, keys, mode = "cbc") {
  const aesEncrypted = await encryptAES(
    data,
    { key: keys.aesKey, iv: keys.aesIv },
    mode
  );

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
  const aesKey = await decryptECC(
    {
      ciphertext: encryptedData.encryptedKey,
      publicKey: encryptedData.eccPublicKey,
      iv: encryptedData.eccIv,
    },
    keys.eccPrivateKey
  );

  return await decryptAES(
    { ciphertext: encryptedData.ciphertext },
    { key: aesKey, iv: encryptedData.iv },
    "cbc"
  );
}

// ========== CLASSICAL CIPHERS ==========

// Caesar Cipher Encryption
async function encryptCaesar(plaintext, shift) {
  shift = shift % 26;
  let ciphertext = "";

  for (let i = 0; i < plaintext.length; i++) {
    let charCode = plaintext.charCodeAt(i);

    if (charCode >= 65 && charCode <= 90) {
      charCode = ((charCode - 65 + shift) % 26) + 65;
    } else if (charCode >= 97 && charCode <= 122) {
      charCode = ((charCode - 97 + shift) % 26) + 97;
    }

    ciphertext += String.fromCharCode(charCode);
  }

  return { ciphertext: Buffer.from(ciphertext, "utf-8") };
}

// Caesar Cipher Decryption
async function decryptCaesar(ciphertext, shift) {
  shift = shift % 26;
  const text = ciphertext.ciphertext.toString("utf-8");
  let plaintext = "";

  for (let i = 0; i < text.length; i++) {
    let charCode = text.charCodeAt(i);

    if (charCode >= 65 && charCode <= 90) {
      charCode = ((charCode - 65 - shift + 26) % 26) + 65;
    } else if (charCode >= 97 && charCode <= 122) {
      charCode = ((charCode - 97 - shift + 26) % 26) + 97;
    }

    plaintext += String.fromCharCode(charCode);
  }

  return Buffer.from(plaintext, "utf-8");
}

// Transposition Cipher Encryption
async function encryptTransposition(plaintext, key) {
  const cleanedText = plaintext
    .toString("utf-8")
    .replace(/[^a-zA-Z]/g, "")
    .toUpperCase();
  const keyLength = key.length;
  const numRows = Math.ceil(cleanedText.length / keyLength);

  const grid = [];
  for (let i = 0; i < numRows; i++) {
    const start = i * keyLength;
    const end = start + keyLength;
    grid.push(cleanedText.slice(start, end));
  }

  const keyOrder = getKeyOrder(key);

  let ciphertext = "";
  for (const col of keyOrder) {
    for (let row = 0; row < numRows; row++) {
      if (col < grid[row].length) {
        ciphertext += grid[row][col];
      }
    }
  }

  return { ciphertext: Buffer.from(ciphertext, "utf-8") };
}

// Transposition Cipher Decryption
async function decryptTransposition(ciphertext, key) {
  const text = ciphertext.ciphertext.toString("utf-8");
  const keyLength = key.length;
  const textLength = text.length;
  const numRows = Math.ceil(textLength / keyLength);

  const keyOrder = getKeyOrder(key);
  const fullCols = textLength % keyLength;
  const rowsPerCol =
    fullCols === 0 ? numRows : Math.ceil(textLength / keyLength);

  const grid = Array(numRows)
    .fill()
    .map(() => Array(keyLength).fill(""));

  let index = 0;
  for (const col of keyOrder) {
    const rowsInThisCol = col < fullCols ? rowsPerCol : rowsPerCol - 1;

    for (let row = 0; row < rowsInThisCol && index < textLength; row++) {
      grid[row][col] = text[index++];
    }
  }

  let plaintext = "";
  for (let row = 0; row < numRows; row++) {
    for (let col = 0; col < keyLength; col++) {
      if (grid[row][col]) {
        plaintext += grid[row][col];
      }
    }
  }

  return Buffer.from(plaintext, "utf-8");
}

// Combined Caesar + Transposition Cipher
async function encryptCaesarTransposition(plaintext, keys) {
  const caesarEncrypted = await encryptCaesar(plaintext, keys.caesarShift);
  const transpositionEncrypted = await encryptTransposition(
    caesarEncrypted.ciphertext.toString("utf-8"),
    keys.transpositionKey
  );

  return {
    ciphertext: transpositionEncrypted.ciphertext,
    caesarShift: keys.caesarShift,
    transpositionKey: keys.transpositionKey,
  };
}

async function decryptCaesarTransposition(encryptedData, keys) {
  const transpositionDecrypted = await decryptTransposition(
    encryptedData,
    keys.transpositionKey
  );

  const caesarDecrypted = await decryptCaesar(
    { ciphertext: transpositionDecrypted },
    keys.caesarShift
  );

  return caesarDecrypted;
}

// Helper function for Transposition Cipher
function getKeyOrder(key) {
  const keyChars = key
    .toUpperCase()
    .split("")
    .map((char, index) => ({
      char,
      index,
    }));

  keyChars.sort((a, b) => a.char.localeCompare(b.char));

  const order = Array(key.length);
  keyChars.forEach((item, sortedIndex) => {
    order[item.index] = sortedIndex;
  });

  return keyChars.map((item) => item.index);
}

// ========== DATABASE FUNCTIONS ==========
async function verifyDatabaseSchema() {
  const connection = await pool.getConnection();
  try {
    await connection.query(`
      CREATE TABLE IF NOT EXISTS enkripsi_data_node_js (
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
        caesar_key INT,
        transposition_key VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    `);
    console.log("Database table verified/created");
  } catch (error) {
    console.error("Failed to verify database schema:", error);
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
    if (!fs.existsSync(folderPath)) {
      throw new Error(`Folder not found: ${folderPath}`);
    }

    const algorithmFolder = `./encrypted_${algorithm.toLowerCase()}`;
    const decryptedFolder = `./decrypted_${algorithm.toLowerCase()}`;

    if (!fs.existsSync(algorithmFolder)) fs.mkdirSync(algorithmFolder);
    if (!fs.existsSync(decryptedFolder)) fs.mkdirSync(decryptedFolder);

    const files = fs.readdirSync(folderPath);
    const results = [];

    for (const file of files) {
      const filePath = path.join(folderPath, file);
      const stats = fs.statSync(filePath);

      if (stats.isFile()) {
        console.log(`Processing file: ${file}`);
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
    }

    return results;
  } catch (error) {
    console.error("Error processing files:", error);
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

  // Encryption
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

  // Decryption
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

  // Calculate metrics
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

  // Prepare result object
  const result = {
    filename,
    algorithm,
    mode,
    block_mode: blockMode,
    original_size: originalSize,
    encrypt_time: encryptTime,
    encrypted_size: encrypted.ciphertext.length,
    decrypt_time: decryptTime,
    entropy_ciphertext: entropyCiphertext,
    entropy_plaintext: entropyPlaintext,
    avalanche_effect: avalancheEffect,
    verified: Buffer.compare(decrypted, content) === 0 ? "Valid" : "Invalid",
    total_process_time: Date.now() - startTime,
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
    caesar_key: keys.caesarShift || null,
    transposition_key: keys.transpositionKey || null,
  };

  return result;
}

// ========== HELPER FUNCTIONS ==========
function generateEncryptionKey(algorithm, blockMode) {
  const possibleKeys = [
    "SECRET",
    "KEY",
    "CIPHER",
    "CODE",
    "CRYPTO",
    "ALGORITHM",
    "ENCRYPT",
    "DECRYPT",
    "SECURITY",
  ];

  switch (algorithm.toUpperCase()) {
    case "AES":
      return {
        key: crypto.randomBytes(32),
        iv: blockMode ? crypto.randomBytes(16) : null,
        type: "symmetric",
      };

    case "ECC":
      const ecdh = crypto.createECDH("c2pnb163v3");
      const publicKey = ecdh.generateKeys("base64");
      const privateKey = ecdh.getPrivateKey("base64");
      return {
        publicKey,
        privateKey,
        type: "asymmetric",
      };

    case "AES+ECC":
      const hybridAesKey = crypto.randomBytes(32);
      const hybridAesIv = blockMode ? crypto.randomBytes(16) : null;

      const { publicKey: eccPubKey, privateKey: eccPrivKey } =
        crypto.generateKeyPairSync("ec", {
          namedCurve: "c2pnb163v3",
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

    case "CAESAR":
      return Math.floor(Math.random() * 25) + 1;

    case "TRANSPOSITION":
      return possibleKeys[Math.floor(Math.random() * possibleKeys.length)];

    case "CAESAR+TRANSPOSITION":
      return {
        caesarShift: Math.floor(Math.random() * 25) + 1,
        transpositionKey:
          possibleKeys[Math.floor(Math.random() * possibleKeys.length)],
        type: "combined",
      };

    default:
      throw new Error(`Algorithm not supported: ${algorithm}`);
  }
}

async function encryptData(data, algorithm, key, iv, mode, blockMode) {
  try {
    switch (algorithm.toUpperCase()) {
      case "AES":
        return await encryptAES(data, key, iv, blockMode || "cbc");
      case "ECC":
        return await encryptECC(data, key.publicKey);
      case "AES+ECC":
        return await encryptHybridAESECC(data, key, blockMode || "cbc");
      case "CAESAR":
        return await encryptCaesar(data.toString("utf-8"), key);
      case "TRANSPOSITION":
        return await encryptTransposition(data, key);
      case "CAESAR+TRANSPOSITION":
        return await encryptCaesarTransposition(data.toString("utf-8"), key);
      default:
        throw new Error(`Encryption algorithm not supported: ${algorithm}`);
    }
  } catch (error) {
    console.error("Encryption failed:", error);
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
      case "AES+ECC":
        return await decryptHybridAESECC(
          encryptedData,
          key,
          blockMode || "cbc"
        );
      case "CAESAR":
        return await decryptCaesar(encryptedData, key);
      case "TRANSPOSITION":
        return await decryptTransposition(encryptedData, key);
      case "CAESAR+TRANSPOSITION":
        return await decryptCaesarTransposition(encryptedData, key);
      default:
        throw new Error(`Decryption algorithm not supported: ${algorithm}`);
    }
  } catch (error) {
    console.error("Decryption failed:", error);
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
    await connection.query(`INSERT INTO enkripsi_data_node_js SET ?`, [result]);
  } catch (error) {
    console.error("Database error:", error);
    throw error;
  } finally {
    connection.release();
  }
}

// ========== MAIN EXECUTION ==========
(async () => {
  try {
    await verifyDatabaseSchema();

    // Example usage with different algorithms
    const results1 = await processFilesFromFolder("./large_files2", "CAESAR");
    const results2 = await processFilesFromFolder(
      "./large_files2",
      "TRANSPOSITION"
    );
    const results3 = await processFilesFromFolder(
      "./large_files2",
      "CAESAR+TRANSPOSITION"
    );
    const results4 = await processFilesFromFolder(
      "./large_files2",
      "AES+ECC",
      "CBC",
      "CBC"
    );

    console.log(
      `Processing complete. Total files processed: ${
        results1.length + results2.length + results3.length + results4.length
      }`
    );
  } catch (error) {
    console.error("Fatal error:", error);
    process.exit(1);
  } finally {
    await pool.end();
    process.exit(0);
  }
})();
