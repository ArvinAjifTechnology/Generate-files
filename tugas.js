const fs = require("fs");
const path = require("path");
const { Transform } = require("stream");
const { pipeline } = require("stream/promises");
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

// ========== ROUTE CIPHER IMPLEMENTATION ==========

class RouteCipherEncryptStream extends Transform {
  constructor(rows, cols, routePattern = "spiral", options = {}) {
    super(options);
    this.rows = rows;
    this.cols = cols;
    this.routePattern = routePattern;
    this.gridSize = rows * cols;
    this.buffer = "";
    this.chunkSize = 1024 * 1024; // Process 1MB chunks
  }

  _transform(chunk, encoding, callback) {
    this.buffer += chunk.toString("utf8");

    // Process complete grids when we have enough data
    while (this.buffer.length >= this.chunkSize) {
      const toProcess = this.buffer.substring(0, this.chunkSize);
      this.buffer = this.buffer.substring(this.chunkSize);
      this.processChunk(toProcess);
    }

    callback();
  }

  _flush(callback) {
    // Process any remaining data
    if (this.buffer.length > 0) {
      this.processChunk(this.buffer);
    }
    callback();
  }

  processChunk(chunk) {
    // Pad the chunk to complete the final grid
    const paddedLength =
      Math.ceil(chunk.length / this.gridSize) * this.gridSize;
    const paddedText = chunk.padEnd(paddedLength, "X");

    // Process each grid in the chunk
    for (let i = 0; i < paddedText.length; i += this.gridSize) {
      const gridText = paddedText.substr(i, this.gridSize);
      const ciphertext = this.encryptGrid(gridText);
      this.push(Buffer.from(ciphertext, "utf8"));
    }
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
      // Left to right on top row
      for (let i = left; i <= right; i++) result += grid[top][i];
      top++;

      // Top to bottom on right column
      for (let i = top; i <= bottom; i++) result += grid[i][right];
      right--;

      if (top <= bottom) {
        // Right to left on bottom row
        for (let i = right; i >= left; i--) result += grid[bottom][i];
        bottom--;
      }

      if (left <= right) {
        // Bottom to top on left column
        for (let i = bottom; i >= top; i--) result += grid[i][left];
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
        for (let j = 0; j < this.cols; j++) result += grid[i][j];
      } else {
        // Right to left for odd rows
        for (let j = this.cols - 1; j >= 0; j--) result += grid[i][j];
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
    this.chunkSize = 1024 * 1024; // Process 1MB chunks
  }

  _transform(chunk, encoding, callback) {
    this.buffer += chunk.toString("utf8");

    // Process complete grids when we have enough data
    while (this.buffer.length >= this.chunkSize) {
      const toProcess = this.buffer.substring(0, this.chunkSize);
      this.buffer = this.buffer.substring(this.chunkSize);
      this.processChunk(toProcess);
    }

    callback();
  }

  _flush(callback) {
    // Process any remaining data
    if (this.buffer.length > 0) {
      this.processChunk(this.buffer);
    }
    callback();
  }

  processChunk(chunk) {
    // Process each grid in the chunk
    for (let i = 0; i < chunk.length; i += this.gridSize) {
      const gridText = chunk.substr(i, this.gridSize);
      const plaintext = this.decryptGrid(gridText);
      this.push(Buffer.from(plaintext, "utf8"));
    }
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
      // Fill left to right on top row
      for (let i = left; i <= right; i++) grid[top][i] = text[index++];
      top++;

      // Fill top to bottom on right column
      for (let i = top; i <= bottom; i++) grid[i][right] = text[index++];
      right--;

      if (top <= bottom) {
        // Fill right to left on bottom row
        for (let i = right; i >= left; i--) grid[bottom][i] = text[index++];
        bottom--;
      }

      if (left <= right) {
        // Fill bottom to top on left column
        for (let i = bottom; i >= top; i--) grid[i][left] = text[index++];
        left++;
      }
    }

    return this.readGrid(grid);
  }

  reverseZigzagRoute(grid, text) {
    let index = 0;
    for (let i = 0; i < this.rows; i++) {
      if (i % 2 === 0) {
        // Left to right for even rows
        for (let j = 0; j < this.cols; j++) grid[i][j] = text[index++];
      } else {
        // Right to left for odd rows
        for (let j = this.cols - 1; j >= 0; j--) grid[i][j] = text[index++];
      }
    }

    return this.readGrid(grid);
  }

  reverseRowRoute(grid, text) {
    let index = 0;
    for (let i = 0; i < this.rows; i++) {
      for (let j = 0; j < this.cols; j++) {
        grid[i][j] = text[index++];
      }
    }
    return this.readGrid(grid);
  }

  reverseColumnRoute(grid, text) {
    let index = 0;
    for (let j = 0; j < this.cols; j++) {
      for (let i = 0; i < this.rows; i++) {
        grid[i][j] = text[index++];
      }
    }
    return this.readGrid(grid);
  }

  readGrid(grid) {
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


// ========== DATABASE FUNCTIONS ==========

async function verifyDatabaseSchema() {
  const connection = await pool.getConnection();
  try {
    await connection.query(`
            CREATE TABLE IF NOT EXISTS route_cipher_data (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
                filename VARCHAR(255) NOT NULL,
                original_size BIGINT NOT NULL,
                encrypted_size BIGINT NOT NULL,
                encrypt_time DOUBLE NOT NULL,
                decrypt_time DOUBLE NOT NULL,
                entropy_plaintext DOUBLE NOT NULL,
                entropy_ciphertext DOUBLE NOT NULL,
                avalanche_effect DOUBLE NOT NULL,
                verified BOOLEAN NOT NULL,
                rows_count INT NOT NULL,
                cols_count INT NOT NULL,
                route_pattern VARCHAR(20) NOT NULL,
                ciphertext_path VARCHAR(255),
                decrypted_path VARCHAR(255),
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

async function storeResultInDatabase(result) {
  const connection = await pool.getConnection();
  try {
    await connection.query(`INSERT INTO route_cipher_data SET ?`, [result]);
  } catch (error) {
    console.error("Database error:", error);
    throw error;
  } finally {
    connection.release();
  }
}

// ========== HELPER FUNCTIONS ==========

function generateRouteCipherKey() {
  return {
    rows: Math.floor(Math.random() * 5) + 3, // 3-7 rows
    cols: Math.floor(Math.random() * 5) + 3, // 3-7 columns
    routePattern: ["spiral", "zigzag", "row", "column"][
      Math.floor(Math.random() * 4)
    ],
  };
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

async function calculateFileHash(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash("sha256");
    const stream = fs.createReadStream(filePath);

    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("end", () => resolve(hash.digest("hex")));
    stream.on("error", reject);
  });
}

// ========== MAIN PROCESSING FUNCTIONS ==========

async function processFileWithRouteCipher(
  filePath,
  algorithmFolder,
  decryptedFolder
) {
  const startTime = Date.now();
  const filename = path.basename(filePath);
  const originalSize = (await fs.promises.stat(filePath)).size;
  const key = generateRouteCipherKey();

  // File paths
  const ciphertextPath = path.join(algorithmFolder, `${filename}.enc`);
  const decryptedPath = path.join(decryptedFolder, filename);

  // Read sample for metrics
  const sampleSize = Math.min(1024, originalSize);
  const sampleBuffer = Buffer.alloc(sampleSize);
  const sampleReadStream = fs.createReadStream(filePath, {
    start: 0,
    end: sampleSize - 1,
  });
  await new Promise((resolve) => {
    sampleReadStream.on("data", (chunk) => sampleBuffer.copy(chunk));
    sampleReadStream.on("end", resolve);
  });

  // Encryption
  const encryptStart = Date.now();
  const inputStream = fs.createReadStream(filePath);
  const outputStream = fs.createWriteStream(ciphertextPath);
  const encryptStream = new RouteCipherEncryptStream(
    key.rows,
    key.cols,
    key.routePattern
  );

  await pipeline(inputStream, encryptStream, outputStream);
  const encryptTime = Date.now() - encryptStart;
  const encryptedSize = (await fs.promises.stat(ciphertextPath)).size;

  // Read encrypted sample for metrics
  const encryptedSampleBuffer = Buffer.alloc(sampleSize);
  const encryptedSampleStream = fs.createReadStream(ciphertextPath, {
    start: 0,
    end: sampleSize - 1,
  });
  await new Promise((resolve) => {
    encryptedSampleStream.on("data", (chunk) =>
      encryptedSampleBuffer.copy(chunk)
    );
    encryptedSampleStream.on("end", resolve);
  });

  // Decryption
  const decryptStart = Date.now();
  const decryptInputStream = fs.createReadStream(ciphertextPath);
  const decryptOutputStream = fs.createWriteStream(decryptedPath);
  const decryptStream = new RouteCipherDecryptStream(
    key.rows,
    key.cols,
    key.routePattern
  );

  await pipeline(decryptInputStream, decryptStream, decryptOutputStream);
  const decryptTime = Date.now() - decryptStart;

  // Calculate metrics
  const entropyPlaintext = calculateEntropy(sampleBuffer);
  const entropyCiphertext = calculateEntropy(encryptedSampleBuffer);

  // For avalanche effect, modify first byte of sample
  const modifiedSample = Buffer.from(sampleBuffer);
  modifiedSample[0] = modifiedSample[0] ^ 1;
  const modifiedEncrypted = await encryptData(modifiedSample, key);
  const avalancheEffect = calculateAvalancheEffect(
    encryptedSampleBuffer,
    modifiedEncrypted.slice(0, sampleSize)
  );

  // Verify by comparing file hashes
  const originalHash = await calculateFileHash(filePath);
  const decryptedHash = await calculateFileHash(decryptedPath);
  const verified = originalHash === decryptedHash;

  // Prepare result object
  const result = {
    filename,
    original_size: originalSize,
    encrypted_size: encryptedSize,
    encrypt_time: encryptTime / 1000,
    decrypt_time: decryptTime / 1000,
    entropy_plaintext: entropyPlaintext,
    entropy_ciphertext: entropyCiphertext,
    avalanche_effect: avalancheEffect,
    verified,
    rows_count: key.rows,
    cols_count: key.cols,
    route_pattern: key.routePattern,
    ciphertext_path: ciphertextPath,
    decrypted_path: decryptedPath,
    total_process_time: (Date.now() - startTime) / 1000,
  };

  return result;
}

async function processFilesFromFolder(folderPath) {
  try {
    await verifyDatabaseSchema();

    const algorithmFolder = path.join(__dirname, "encrypted_route");
    const decryptedFolder = path.join(__dirname, "decrypted_route");

    if (!fs.existsSync(algorithmFolder))
      fs.mkdirSync(algorithmFolder, { recursive: true });
    if (!fs.existsSync(decryptedFolder))
      fs.mkdirSync(decryptedFolder, { recursive: true });

    const files = fs
      .readdirSync(folderPath)
      .map((file) => ({
        file,
        path: path.join(folderPath, file),
        stats: fs.statSync(path.join(folderPath, file)),
      }))
      .filter((f) => f.stats.isFile())
      .sort((a, b) => a.stats.size - b.stats.size);

    const results = [];

    for (const { file, path: filePath } of files) {
      console.log(`Processing file: ${file}`);
      const result = await processFileWithRouteCipher(
        filePath,
        algorithmFolder,
        decryptedFolder
      );
      await storeResultInDatabase(result);
      results.push(result);
    }

    return results;
  } catch (error) {
    console.error("Error processing files:", error);
    throw error;
  }
}

// Helper function for sample encryption
async function encryptData(data, key) {
  return new Promise((resolve) => {
    const chunks = [];
    const encryptStream = new RouteCipherEncryptStream(
      key.rows,
      key.cols,
      key.routePattern
    );
    const input = new (require("stream").PassThrough)();

    input.end(data);
    encryptStream.on("data", (chunk) => chunks.push(chunk));
    encryptStream.on("end", () => resolve(Buffer.concat(chunks)));

    input.pipe(encryptStream);
  });
}

// ========== MAIN EXECUTION ==========

(async () => {
  try {
    const results = await processFilesFromFolder("./large_files2");
    console.log(`Processing complete. ${results.length} files processed.`);
  } catch (error) {
    console.error("Fatal error:", error);
  } finally {
    await pool.end();
  }
})();
