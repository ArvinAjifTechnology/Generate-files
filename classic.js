const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const mysql = require("mysql2/promise");
const { pipeline } = require("stream");
const { promisify } = require("util");
const pipelineAsync = promisify(pipeline);
const { Transform } = require("stream");

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

// ========== ENCRYPTION/DECRYPTION FUNCTIONS WITH STREAMS ==========

// AES Encryption Stream
function createAESEncryptStream(key, iv, mode = "cbc") {
  const cipher = crypto.createCipheriv(
    `aes-256-${mode.toLowerCase()}`,
    key.key,
    key.iv
  );
  return cipher;
}

// AES Decryption Stream
function createAESDecryptStream(key, iv, mode = "cbc") {
  const decipher = crypto.createDecipheriv(
    `aes-256-${mode.toLowerCase()}`,
    key.key,
    key.iv
  );
  return decipher;
}

// ECC Encryption (still needs full data for key derivation)
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

// ECC Decryption (still needs full data)
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

// Hybrid AES+ECC Encryption Stream
function createHybridAESECCEncryptStream(keys, mode = "cbc") {
  return createAESEncryptStream({ key: keys.aesKey, iv: keys.aesIv }, mode);
}

// Hybrid AES+ECC Decryption Stream
function createHybridAESECCDecryptStream(keys, mode = "cbc") {
  return createAESDecryptStream({ key: keys.aesKey, iv: keys.aesIv }, mode);
}

// ========== CLASSICAL CIPHERS WITH STREAMS ==========

// Caesar Cipher Transform Stream
class CaesarCipherStream extends Transform {
  constructor(shift, options = {}) {
    super(options);
    this.shift = shift % 26;
  }

  _transform(chunk, encoding, callback) {
    let result = "";
    for (let i = 0; i < chunk.length; i++) {
      let charCode = chunk[i];

      if (charCode >= 65 && charCode <= 90) {
        // A-Z
        charCode = ((charCode - 65 + this.shift) % 26) + 65;
      } else if (charCode >= 97 && charCode <= 122) {
        // a-z
        charCode = ((charCode - 97 + this.shift) % 26) + 97;
      }

      result += String.fromCharCode(charCode);
    }
    this.push(Buffer.from(result, "utf-8"));
    callback();
  }
}

class CaesarDecipherStream extends Transform {
  constructor(shift, options = {}) {
    super(options);
    this.shift = shift % 26;
  }

  _transform(chunk, encoding, callback) {
    let result = "";
    for (let i = 0; i < chunk.length; i++) {
      let charCode = chunk[i];

      if (charCode >= 65 && charCode <= 90) {
        // A-Z
        charCode = ((charCode - 65 - this.shift + 26) % 26) + 65;
      } else if (charCode >= 97 && charCode <= 122) {
        // a-z
        charCode = ((charCode - 97 - this.shift + 26) % 26) + 97;
      }

      result += String.fromCharCode(charCode);
    }
    this.push(Buffer.from(result, "utf-8"));
    callback();
  }
}
class TranspositionEncryptStream extends Transform {
  constructor(key, options = {}) {
    super(options);
    this.key = key;
    this.keyLen = key.length;
    this.remainder = Buffer.alloc(0);

    // Urutan kolom dari key
    this.columnOrder = [...key]
      .map((char, index) => ({ char, index }))
      .sort((a, b) => a.char.localeCompare(b.char))
      .map((obj) => obj.index);
  }

  _transform(chunk, _, cb) {
    const buffer = Buffer.concat([this.remainder, chunk]);
    const blockSize = this.keyLen;
    const fullBlocks = Math.floor(buffer.length / blockSize);
    const usableLength = fullBlocks * blockSize;

    for (let i = 0; i < usableLength; i += blockSize) {
      const block = buffer.subarray(i, i + blockSize);
      const encrypted = Buffer.alloc(blockSize);
      for (let j = 0; j < blockSize; j++) {
        encrypted[j] = block[this.columnOrder[j]];
      }
      this.push(encrypted);
    }

    this.remainder = buffer.subarray(usableLength); // Simpan sisa untuk _flush
    cb();
  }

  _flush(cb) {
    if (this.remainder.length > 0) {
      const padded = Buffer.alloc(this.keyLen, "X".charCodeAt(0));
      this.remainder.copy(padded);
      const encrypted = Buffer.alloc(this.keyLen);
      for (let j = 0; j < this.keyLen; j++) {
        encrypted[j] = padded[this.columnOrder[j]];
      }
      this.push(encrypted);
    }
    cb();
  }
}

class TranspositionDecryptStream extends Transform {
  constructor(key, options = {}) {
    super(options);
    this.key = key;
    this.keyLen = key.length;
    this.buffer = Buffer.alloc(0);

    this.keyOrder = key
      .split("")
      .map((char, idx) => ({ char, idx }))
      .sort((a, b) => a.char.localeCompare(b.char))
      .map((obj) => obj.idx);

    this.inverseKeyOrder = [];
    this.keyOrder.forEach((val, idx) => {
      this.inverseKeyOrder[val] = idx;
    });
  }

  _transform(chunk, encoding, callback) {
    this.buffer = Buffer.concat([this.buffer, chunk]);

    while (this.buffer.length >= this.keyLen) {
      const block = this.buffer.slice(0, this.keyLen);
      this.buffer = this.buffer.slice(this.keyLen);

      let rearranged = Buffer.alloc(this.keyLen);
      for (let i = 0; i < this.keyLen; i++) {
        rearranged[this.inverseKeyOrder[i]] = block[i];
      }

      this.push(rearranged);
    }

    callback();
  }

  _flush(callback) {
    if (this.buffer.length > 0) {
      // Final block (could be padded with 'X')
      const padded = Buffer.alloc(this.keyLen, "X".charCodeAt(0));
      this.buffer.copy(padded, 0, 0, this.buffer.length);

      let rearranged = Buffer.alloc(this.keyLen);
      for (let i = 0; i < this.keyLen; i++) {
        rearranged[this.inverseKeyOrder[i]] = padded[i];
      }

      this.push(rearranged);
    }
    callback();
  }
}

class RouteCipherEncryptStream extends Transform {
  constructor(rows, cols, routePattern = "spiral", options = {}) {
    super(options);
    this.rows = rows;
    this.cols = cols;
    this.routePattern = routePattern;
    this.buffer = "";
    this.gridSize = rows * cols;
  }

  _transform(chunk, encoding, callback) {
    this.buffer += chunk.toString("utf8");
    callback();
  }

  _flush(callback) {
    // Pad the buffer if needed
    const paddedLength =
      Math.ceil(this.buffer.length / this.gridSize) * this.gridSize;
    const paddedText = this.buffer.padEnd(paddedLength, "X");

    // Process each grid
    for (let i = 0; i < paddedText.length; i += this.gridSize) {
      const gridText = paddedText.substr(i, this.gridSize);
      const ciphertext = this.encryptGrid(gridText);
      this.push(Buffer.from(ciphertext, "utf8"));
    }

    callback();
  }

  encryptGrid(text) {
    // Create grid
    const grid = [];
    for (let i = 0; i < this.rows; i++) {
      const start = i * this.cols;
      grid.push(text.substr(start, this.cols).split(""));
    }

    // Encrypt based on route pattern
    switch (this.routePattern) {
      case "spiral":
        return this.spiralRoute(grid);
      case "zigzag":
        return this.zigzagRoute(grid);
      case "row":
        return this.rowRoute(grid);
      case "column":
        return this.columnRoute(grid);
      default:
        return this.spiralRoute(grid);
    }
  }

  spiralRoute(grid) {
    let result = "";
    let top = 0,
      bottom = this.rows - 1;
    let left = 0,
      right = this.cols - 1;

    while (top <= bottom && left <= right) {
      // Traverse from left to right on top row
      for (let i = left; i <= right; i++) {
        result += grid[top][i];
      }
      top++;

      // Traverse from top to bottom on right column
      for (let i = top; i <= bottom; i++) {
        result += grid[i][right];
      }
      right--;

      if (top <= bottom) {
        // Traverse from right to left on bottom row
        for (let i = right; i >= left; i--) {
          result += grid[bottom][i];
        }
        bottom--;
      }

      if (left <= right) {
        // Traverse from bottom to top on left column
        for (let i = bottom; i >= top; i--) {
          result += grid[i][left];
        }
        left++;
      }
    }

    return result;
  }

  zigzagRoute(grid) {
    let result = "";
    for (let i = 0; i < this.rows; i++) {
      if (i % 2 === 0) {
        // Left to right for even rows
        for (let j = 0; j < this.cols; j++) {
          result += grid[i][j];
        }
      } else {
        // Right to left for odd rows
        for (let j = this.cols - 1; j >= 0; j--) {
          result += grid[i][j];
        }
      }
    }
    return result;
  }

  rowRoute(grid) {
    let result = "";
    for (let i = 0; i < this.rows; i++) {
      for (let j = 0; j < this.cols; j++) {
        result += grid[i][j];
      }
    }
    return result;
  }

  columnRoute(grid) {
    let result = "";
    for (let j = 0; j < this.cols; j++) {
      for (let i = 0; i < this.rows; i++) {
        result += grid[i][j];
      }
    }
    return result;
  }
}
class RouteCipherDecryptStream extends Transform {
  constructor(rows, cols, routePattern = "spiral", options = {}) {
    super(options);
    this.rows = rows;
    this.cols = cols;
    this.routePattern = routePattern;
    this.gridSize = rows * cols;
    this.buffer = "";
  }

  _transform(chunk, encoding, callback) {
    this.buffer += chunk.toString("utf8");
    callback();
  }

  _flush(callback) {
    // Process each grid
    for (let i = 0; i < this.buffer.length; i += this.gridSize) {
      const gridText = this.buffer.substr(i, this.gridSize);
      const plaintext = this.decryptGrid(gridText);
      this.push(Buffer.from(plaintext, "utf8"));
    }

    callback();
  }

  decryptGrid(text) {
    // Create empty grid
    const grid = Array(this.rows)
      .fill()
      .map(() => Array(this.cols).fill(""));

    // Fill grid based on route pattern
    switch (this.routePattern) {
      case "spiral":
        return this.reverseSpiralRoute(grid, text);
      case "zigzag":
        return this.reverseZigzagRoute(grid, text);
      case "row":
        return this.reverseRowRoute(grid, text);
      case "column":
        return this.reverseColumnRoute(grid, text);
      default:
        return this.reverseSpiralRoute(grid, text);
    }
  }

  reverseSpiralRoute(grid, text) {
    let top = 0,
      bottom = this.rows - 1;
    let left = 0,
      right = this.cols - 1;
    let index = 0;

    while (top <= bottom && left <= right) {
      // Fill from left to right on top row
      for (let i = left; i <= right; i++) {
        grid[top][i] = text[index++];
      }
      top++;

      // Fill from top to bottom on right column
      for (let i = top; i <= bottom; i++) {
        grid[i][right] = text[index++];
      }
      right--;

      if (top <= bottom) {
        // Fill from right to left on bottom row
        for (let i = right; i >= left; i--) {
          grid[bottom][i] = text[index++];
        }
        bottom--;
      }

      if (left <= right) {
        // Fill from bottom to top on left column
        for (let i = bottom; i >= top; i--) {
          grid[i][left] = text[index++];
        }
        left++;
      }
    }

    // Read grid row by row
    let result = "";
    for (let i = 0; i < this.rows; i++) {
      for (let j = 0; j < this.cols; j++) {
        result += grid[i][j];
      }
    }

    return result;
  }

  reverseZigzagRoute(grid, text) {
    let index = 0;
    for (let i = 0; i < this.rows; i++) {
      if (i % 2 === 0) {
        // Left to right for even rows
        for (let j = 0; j < this.cols; j++) {
          grid[i][j] = text[index++];
        }
      } else {
        // Right to left for odd rows
        for (let j = this.cols - 1; j >= 0; j--) {
          grid[i][j] = text[index++];
        }
      }
    }

    // Read grid row by row
    let result = "";
    for (let i = 0; i < this.rows; i++) {
      for (let j = 0; j < this.cols; j++) {
        result += grid[i][j];
      }
    }

    return result;
  }

  reverseRowRoute(grid, text) {
    let index = 0;
    for (let i = 0; i < this.rows; i++) {
      for (let j = 0; j < this.cols; j++) {
        grid[i][j] = text[index++];
      }
    }

    // Read grid row by row
    let result = "";
    for (let i = 0; i < this.rows; i++) {
      for (let j = 0; j < this.cols; j++) {
        result += grid[i][j];
      }
    }

    return result;
  }

  reverseColumnRoute(grid, text) {
    let index = 0;
    for (let j = 0; j < this.cols; j++) {
      for (let i = 0; i < this.rows; i++) {
        grid[i][j] = text[index++];
      }
    }

    // Read grid row by row
    let result = "";
    for (let i = 0; i < this.rows; i++) {
      for (let j = 0; j < this.cols; j++) {
        result += grid[i][j];
      }
    }

    return result;
  }
}

// Transposition Cipher (needs full data)
async function encryptTransposition(plaintext, key) {
  if (!key || key.length === 0) throw new Error("Key cannot be empty");

  plaintext = plaintext.toString();
  const keyLength = key.length;
  const numRows = Math.ceil(plaintext.length / keyLength);
  const paddedText = plaintext.padEnd(numRows * keyLength, "X");

  const matrix = [];
  for (let i = 0; i < numRows; i++) {
    const row = paddedText.slice(i * keyLength, (i + 1) * keyLength);
    matrix.push([...row]);
  }

  const keyOrder = getKeyOrder(key);
  let ciphertext = "";
  for (const col of keyOrder) {
    for (let row = 0; row < numRows; row++) {
      ciphertext += matrix[row][col];
    }
  }

  return {
    ciphertext: Buffer.from(ciphertext, "utf-8"),
    length: plaintext.length,
  };
}

async function decryptTransposition({ ciphertext, length }, key) {
  if (!key || key.length === 0) throw new Error("Key cannot be empty");

  const text = ciphertext.toString("utf-8");
  const keyLength = key.length;
  const numRows = Math.ceil(text.length / keyLength);

  const keyOrder = getKeyOrder(key);

  const fullCells = text.length;
  const numShortCols = keyLength * numRows - fullCells;
  const colLengths = Array(keyLength).fill(numRows);
  for (let i = keyLength - 1; i >= keyLength - numShortCols; i--) {
    colLengths[keyOrder[i]] -= 1;
  }

  const cols = Array(keyLength)
    .fill(null)
    .map(() => []);
  let idx = 0;
  for (let i = 0; i < keyLength; i++) {
    const colIdx = keyOrder[i];
    const len = colLengths[colIdx];
    cols[colIdx] = text.slice(idx, idx + len).split("");
    idx += len;
  }

  let plaintext = "";
  for (let row = 0; row < numRows; row++) {
    for (let col = 0; col < keyLength; col++) {
      plaintext += cols[col][row] || "";
    }
  }

  return Buffer.from(plaintext.slice(0, length), "utf-8");
}

function getKeyOrder(key) {
  return Array.from(key)
    .map((char, index) => ({ char, index }))
    .sort((a, b) => a.char.localeCompare(b.char) || a.index - b.index)
    .map(({ index }) => index);
}
// Add this function to your helper functions section
async function encryptData(data, algorithm, keys, iv, mode, blockMode) {
  switch (algorithm.toUpperCase()) {
    case "AES":
      const cipher = crypto.createCipheriv(
        `aes-256-${blockMode || "cbc"}`,
        keys.key,
        iv
      );
      return {
        ciphertext: Buffer.concat([cipher.update(data), cipher.final()]),
      };

    case "CAESAR":
      return new Promise((resolve, reject) => {
        const chunks = [];
        const caesarStream = new CaesarCipherStream(keys);
        const { PassThrough } = require("stream");
        const input = new PassThrough();

        input.end(data);

        caesarStream.on("data", (chunk) => chunks.push(chunk));
        caesarStream.on("end", () =>
          resolve({ ciphertext: Buffer.concat(chunks) })
        );
        caesarStream.on("error", reject);

        input.pipe(caesarStream);
      });

    case "TRANSPOSITION":
      return encryptTransposition(data, keys);

    case "CAESAR+TRANSPOSITION":
      return encryptCaesarTransposition(data, keys);
    case "ROUTE":
      const routeEncrypted = await new Promise((resolve, reject) => {
        const chunks = [];
        const routeStream = new RouteCipherEncryptStream(
          keys.rows,
          keys.cols,
          keys.routePattern
        );
        const { PassThrough } = require("stream");
        const input = new PassThrough();

        input.end(Buffer.from(data, "utf8"));

        routeStream.on("data", (chunk) => chunks.push(chunk));
        routeStream.on("end", () => resolve(Buffer.concat(chunks)));
        routeStream.on("error", reject);

        input.pipe(routeStream);
      });
      return { ciphertext: routeEncrypted };

    case "AES+ECC":
      const hybridCipher = crypto.createCipheriv(
        `aes-256-${blockMode || "cbc"}`,
        keys.aesKey,
        keys.aesIv
      );
      return {
        ciphertext: Buffer.concat([
          hybridCipher.update(data),
          hybridCipher.final(),
        ]),
      };

    default:
      throw new Error(`Algorithm not supported: ${algorithm}`);
  }
}
// Combined Caesar + Transposition Cipher (needs full data)
async function encryptCaesarTransposition(plaintext, keys) {
  if (!keys || !keys.caesarShift || !keys.transpositionKey) {
    throw new Error("Both caesarShift and transpositionKey are required");
  }

  const caesarEncrypted = await new Promise((resolve, reject) => {
    const chunks = [];
    const caesarStream = new CaesarCipherStream(keys.caesarShift);
    const { PassThrough } = require("stream");
    const input = new PassThrough();

    input.end(Buffer.from(plaintext, "utf-8"));

    caesarStream.on("data", (chunk) => chunks.push(chunk));
    caesarStream.on("end", () => resolve(Buffer.concat(chunks)));
    caesarStream.on("error", reject);

    input.pipe(caesarStream);
  });

  const transpositionEncrypted = await encryptTransposition(
    caesarEncrypted,
    keys.transpositionKey
  );

  return {
    ciphertext: transpositionEncrypted.ciphertext,
    caesarShift: keys.caesarShift,
    transpositionKey: keys.transpositionKey,
  };
}

async function decryptCaesarTransposition(encryptedData, keys) {
  if (!keys || !keys.caesarShift || !keys.transpositionKey) {
    throw new Error("Both caesarShift and transpositionKey are required");
  }

  const transpositionDecrypted = await decryptTransposition(
    encryptedData,
    keys.transpositionKey
  );

  const caesarDecrypted = await new Promise((resolve, reject) => {
    const chunks = [];
    const caesarStream = new CaesarDecipherStream(keys.caesarShift);
    const { PassThrough } = require("stream");
    const input = new PassThrough();

    input.end(transpositionDecrypted);

    caesarStream.on("data", (chunk) => chunks.push(chunk));
    caesarStream.on("end", () => resolve(Buffer.concat(chunks)));
    caesarStream.on("error", reject);

    input.pipe(caesarStream);
  });

  return caesarDecrypted;
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

// ========== STREAM-BASED PROCESSING FUNCTIONS ==========
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

    const algorithmFolder = path.join(
      __dirname,
      `./classic_cryptography/encrypted_${algorithm.toLowerCase()}`
    );
    const decryptedFolder = path.join(
      __dirname,
      `./classic_cryptography/decrypted_${algorithm.toLowerCase()}`
    );

    if (!fs.existsSync(algorithmFolder))
      fs.mkdirSync(algorithmFolder, { recursive: true });
    if (!fs.existsSync(decryptedFolder))
      fs.mkdirSync(decryptedFolder, { recursive: true });

    const files = fs
      .readdirSync(folderPath)
      .map((file) => {
        const filePath = path.join(folderPath, file);
        const stats = fs.statSync(filePath);
        return { file, size: stats.size };
      })
      .filter((f) => fs.statSync(path.join(folderPath, f.file)).isFile())
      .sort((a, b) => a.size - b.size);

    const results = [];

    for (const { file } of files) {
      const filePath = path.join(folderPath, file);
      console.log(`Processing file: ${file}`);
      const result = await processFileWithStreams(
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
    console.error("Error processing files:", error);
    throw error;
  }
}

async function processFileWithStreams(
  filePath,
  algorithm,
  mode,
  blockMode,
  algorithmFolder,
  decryptedFolder
) {
  const startTime = Date.now();
  const filename = path.basename(filePath);
  const originalSize = (await fs.promises.stat(filePath)).size;
  const keys = generateEncryptionKey(algorithm, blockMode);

  // For transposition ciphers, store the original size in the keys object
  if (
    algorithm.toUpperCase() === "TRANSPOSITION" ||
    algorithm.toUpperCase() === "CAESAR+TRANSPOSITION"
  ) {
    keys.originalSize = originalSize;
  }
  // File paths
  const ciphertextPath = path.join(algorithmFolder, `${filename}.enc`);
  const decryptedPath = path.join(decryptedFolder, filename);

  // For metrics calculation
  const sampleSize = Math.min(1024, originalSize);
  const sampleBuffer = Buffer.alloc(sampleSize);
  const sampleReadStream = fs.createReadStream(filePath, {
    start: 0,
    end: sampleSize - 1,
  });
  await new Promise((resolve) => {
    sampleReadStream.on("data", (chunk) => chunk.copy(sampleBuffer));
    sampleReadStream.on("end", resolve);
  });

  // Encryption
  const encryptStart = Date.now();
  let encryptedSize;

  if (
    algorithm.toUpperCase() === "TRANSPOSITION" ||
    algorithm.toUpperCase() === "CAESAR+TRANSPOSITION"
  ) {
    // For transposition cipher, read the whole file first
    const data = await fs.promises.readFile(filePath);
    let encryptedData;

    if (algorithm.toUpperCase() === "TRANSPOSITION") {
      encryptedData = await encryptTransposition(data, keys);
    } else {
      encryptedData = await encryptCaesarTransposition(data, keys);
    }

    await fs.promises.writeFile(ciphertextPath, encryptedData.ciphertext);
    encryptedSize = encryptedData.ciphertext.length;
  } else {
    // For streamable ciphers
    encryptedSize = await encryptWithStream(
      filePath,
      ciphertextPath,
      algorithm,
      keys,
      mode,
      blockMode
    );
  }

  const encryptTime = Date.now() - encryptStart;

  // Read encrypted sample for metrics
  const encryptedSampleBuffer = Buffer.alloc(sampleSize);
  const encryptedSampleReadStream = fs.createReadStream(ciphertextPath, {
    start: 0,
    end: sampleSize - 1,
  });
  await new Promise((resolve) => {
    encryptedSampleReadStream.on("data", (chunk) =>
      chunk.copy(encryptedSampleBuffer)
    );
    encryptedSampleReadStream.on("end", resolve);
  });

  // Decryption
  const decryptStart = Date.now();

  if (
    algorithm.toUpperCase() === "TRANSPOSITION" ||
    algorithm.toUpperCase() === "CAESAR+TRANSPOSITION"
  ) {
    // For transposition cipher, read the whole file first
    const encryptedData = await fs.promises.readFile(ciphertextPath);
    let decryptedData;

    if (algorithm.toUpperCase() === "TRANSPOSITION") {
      decryptedData = await decryptTransposition(
        { ciphertext: encryptedData, length: originalSize },
        keys
      );
    } else {
      decryptedData = await decryptCaesarTransposition(
        { ciphertext: encryptedData, length: originalSize },
        keys
      );
    }

    await fs.promises.writeFile(decryptedPath, decryptedData);
  } else {
    // For streamable ciphers
    await decryptWithStream(
      ciphertextPath,
      decryptedPath,
      algorithm,
      keys,
      mode,
      blockMode
    );
  }

  const decryptTime = Date.now() - decryptStart;

  // Rest of the function remains the same...
  // Calculate metrics
  const entropyPlaintext = calculateEntropy(sampleBuffer);
  const entropyCiphertext = calculateEntropy(encryptedSampleBuffer);

  // For avalanche effect, modify first byte of sample
  const modifiedSample = Buffer.from(sampleBuffer);
  modifiedSample[0] = modifiedSample[0] ^ 1;
  const modifiedEncrypted = await encryptData(
    modifiedSample,
    algorithm,
    keys,
    keys.iv,
    mode,
    blockMode
  );
  const avalancheEffect = calculateAvalancheEffect(
    encryptedSampleBuffer,
    modifiedEncrypted.ciphertext.slice(0, sampleSize)
  );

  // Verify by comparing file hashes
  const originalHash = await calculateFileHash(filePath);
  const decryptedHash = await calculateFileHash(decryptedPath);
  const verified = originalHash === decryptedHash ? "Valid" : "Invalid";

  // Prepare result object
  const result = {
    filename,
    algorithm,
    mode,
    block_mode: blockMode,
    original_size: originalSize,
    encrypt_time: (encryptTime / 1000).toFixed(4),
    encrypted_size: encryptedSize,
    decrypt_time: (decryptTime / 1000).toFixed(4),
    entropy_ciphertext: entropyCiphertext,
    entropy_plaintext: entropyPlaintext,
    avalanche_effect: avalancheEffect,
    verified,
    total_process_time: ((Date.now() - startTime) / 1000).toFixed(4),
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

async function encryptWithStream(
  inputPath,
  outputPath,
  algorithm,
  keys,
  mode,
  blockMode
) {
  const inputStream = fs.createReadStream(inputPath);
  const outputStream = fs.createWriteStream(outputPath);

  let transformStream;
  switch (algorithm.toUpperCase()) {
    case "AES":
      transformStream = createAESEncryptStream(
        { key: keys.key, iv: keys.iv },
        blockMode || "cbc"
      );
      break;
    case "CAESAR":
      transformStream = new CaesarCipherStream(keys);
      break;
    case "TRANSPOSITION":
      transformStream = new TranspositionEncryptStream(keys);
      break;
    case "AES+ECC":
      transformStream = createHybridAESECCEncryptStream(
        keys,
        blockMode || "cbc"
      );
      break;
    default:
      throw new Error(
        `Stream encryption not supported for algorithm: ${algorithm}`
      );
  }

  // Pipeline data through input -> transform -> output streams
  await pipelineAsync(inputStream, transformStream, outputStream);
  return (await fs.promises.stat(outputPath)).size;
}


async function decryptWithStream(
  inputPath,
  outputPath,
  algorithm,
  keys,
  mode,
  blockMode
) {
  const inputStream = fs.createReadStream(inputPath);
  const outputStream = fs.createWriteStream(outputPath);

  let transformStream;
  switch (algorithm.toUpperCase()) {
    case "AES":
      transformStream = createAESDecryptStream(
        { key: keys.key, iv: keys.iv },
        blockMode || "cbc"
      );
      break;

    case "CAESAR":
      transformStream = new CaesarDecipherStream(keys);
      break;

    case "TRANSPOSITION":
      transformStream = new TranspositionDecryptStream(keys);
      break;

    case "AES+ECC":
      transformStream = createHybridAESECCDecryptStream(
        keys,
        blockMode || "cbc"
      );
      break;

    case "CAESAR+TRANSPOSITION":
      // Untuk kombinasi CAESAR+TRANSPOSITION, urutan decrypt adalah kebalikan dari encrypt
      const transpositionStream = new TranspositionDecryptStream(
        keys.transpositionKey
      );
      transpositionStream.originalSize = keys.originalSize;

      const caesarStream = new CaesarDecipherStream(keys.caesarShift);

      await pipelineAsync(
        inputStream,
        transpositionStream,
        caesarStream,
        outputStream
      );
      return (await fs.promises.stat(outputPath)).size;

    case "ROUTE":
      // Route cipher biasanya tidak cocok dengan streaming biasa karena prosesnya perlu data lengkap
      const encryptedBuffer = await fs.promises.readFile(inputPath);
      const decryptedBuffer = await decryptRouteCipher(
        encryptedBuffer,
        keys.rows,
        keys.cols,
        keys.routePattern,
        keys.originalSize
      );
      await fs.promises.writeFile(outputPath, decryptedBuffer);
      return decryptedBuffer.length;

    default:
      throw new Error(`Unsupported algorithm: ${algorithm}`);
  }

  // Pipeline untuk algoritma yang support streaming
  await pipelineAsync(inputStream, transformStream, outputStream);

  return (await fs.promises.stat(outputPath)).size;
}

async function decryptWithStream(
  inputPath,
  outputPath,
  algorithm,
  keys,
  mode,
  blockMode
) {
  const inputStream = fs.createReadStream(inputPath);
  const outputStream = fs.createWriteStream(outputPath);

  let transformStream;
  switch (algorithm.toUpperCase()) {
    case "AES":
      transformStream = createAESDecryptStream(
        { key: keys.key, iv: keys.iv },
        blockMode || "cbc"
      );
      break;
    case "CAESAR":
      transformStream = new CaesarDecipherStream(keys);
      break;
    case "TRANSPOSITION":
      // Need original size - you might need to store this when encrypting
      transformStream = new TranspositionDecryptStream(keys, keys.originalSize);
      break;
    case "AES+ECC":
      transformStream = createHybridAESECCDecryptStream(
        keys,
        blockMode || "cbc"
      );
      break;
    case "CAESAR+TRANSPOSITION":
      // For combined cipher, first Transposition then Caesar
      const transpositionStream = new TranspositionDecryptStream(
        keys.transpositionKey,
        keys.originalSize
      );
      const caesarStream = new CaesarDecipherStream(keys.caesarShift);

      // Pipe through both transforms
      await pipelineAsync(
        inputStream,
        transpositionStream,
        caesarStream,
        outputStream
      );
      return;
    default:
      throw new Error(
        `Stream decryption not supported for algorithm: ${algorithm}`
      );
  }

  await pipelineAsync(inputStream, transformStream, outputStream);
}

async function calculateFileHash(filePath) {
  const hash = crypto.createHash("sha256");
  const stream = fs.createReadStream(filePath);

  return new Promise((resolve, reject) => {
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("end", () => resolve(hash.digest("hex")));
    stream.on("error", reject);
  });
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

    case "ROUTE":
      return {
        rows: Math.floor(Math.random() * 5) + 3, // 3-7 rows
        cols: Math.floor(Math.random() * 5) + 3, // 3-7 columns
        routePattern: ["spiral", "zigzag", "row", "column"][
          Math.floor(Math.random() * 4)
        ],
        type: "route",
      };

    default:
      throw new Error(`Algorithm not supported: ${algorithm}`);
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
    // const results1 = await processFilesFromFolder("./large_files2", "CAESAR");
    // const results2 = await processFilesFromFolder(
    //   "./large_files2",
    //   "TRANSPOSITION"
    // );
    const results3 = await processFilesFromFolder(
      "./large_files2",
      "AES+ECC"
    );

    console.log(
      `Processing complete. Total files processed: ${
        results1.length + results2.length + results3.length
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
