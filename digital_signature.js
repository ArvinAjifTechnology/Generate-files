const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const mysql = require('mysql2/promise');
const { PDFDocument } = require('pdf-lib');
const { extract } = require('docx-parser');
const { jsQR } = require('jsqr');
const Jimp = require('jimp');

// Database configuration
const dbConfig = {
  host: 'localhost',
  user: 'root',
  password: 'root',
  database: 'kriptografi',
  connectionLimit: 10
};

// Create a connection pool
const pool = mysql.createPool(dbConfig);

// Verify/Create database table with all required columns
async function verifyDatabaseSchema() {
  const connection = await pool.getConnection();
  try {
    await connection.query(`
      CREATE TABLE IF NOT EXISTS digital_signatures (
        id INT AUTO_INCREMENT PRIMARY KEY,
        filename VARCHAR(255) NOT NULL,
        file_size_mb FLOAT,
        private_key BLOB,
        public_key BLOB,
        algorithm VARCHAR(50) NOT NULL,
        mode VARCHAR(50),
        block_mode VARCHAR(50),
        stream_mode VARCHAR(50),
        original_size INT,
        hash TEXT NOT NULL,
        hash_time FLOAT,
        message_digest TEXT,
        avalanche FLOAT,
        encryption BLOB,
        encrypt_time FLOAT,
        encrypted_size INT,
        entropy FLOAT,
        ciphertext BLOB,
        decryption BLOB,
        decrypt_time FLOAT,
        decrypted_size INT,
        verified VARCHAR(20) NOT NULL,
        qr_code TEXT,
        total_process_time FLOAT,
        file_load_time FLOAT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('Database table verified/created');
  } catch (error) {
    console.error('Database schema verification failed:', error);
    throw error;
  } finally {
    connection.release();
  }
}

// Main processing function
async function processFilesFromFolder(folderPath, algorithm, mode, blockMode = null, streamMode = null) {
  try {
    // Verify folder exists
    if (!fs.existsSync(folderPath)) {
      throw new Error(`Folder not found: ${folderPath}`);
    }

    const files = fs.readdirSync(folderPath);
    const results = [];
    
    for (const file of files) {
      const filePath = path.join(folderPath, file);
      const stats = fs.statSync(filePath);
      
      if (stats.isFile()) {
        console.log(`Processing file: ${file}`);
        const result = await processSingleFile(filePath, algorithm, mode, blockMode, streamMode);
        results.push(result);
        
        // Store in database
        await storeResultInDatabase(result);
      }
    }
    
    return results;
  } catch (error) {
    console.error('Error processing files:', error);
    throw error;
  }
}

// Process a single file
async function processSingleFile(filePath, algorithm, mode, blockMode, streamMode) {
  const startTotalTime = Date.now();
  const filename = path.basename(filePath);
  const extension = path.extname(filePath).toLowerCase();
  const stats = fs.statSync(filePath);
  let content = '';
  
  // Read file content based on type
  try {
    if (extension === '.txt') {
      content = fs.readFileSync(filePath, 'utf-8');
    } else if (extension === '.pdf') {
      const pdfBytes = fs.readFileSync(filePath);
      const pdfDoc = await PDFDocument.load(pdfBytes);
      content = (await Promise.all(pdfDoc.getPages().map(p => p.getText()))).join('\n');
    } else if (extension === '.docx') {
      content = await new Promise((resolve, reject) => {
        extract(filePath, (err, text) => err ? reject(err) : resolve(text));
      });
    }
  } catch (error) {
    console.error(`Error reading ${filename}:`, error);
    throw error;
  }

  // Normalize content
  content = content.replace(/\s+/g, ' ').trim();

  // Generate cryptographic keys
  const keys = generateKeys(algorithm);

  // Hash the content
  const hashStart = Date.now();
  const hash = crypto.createHash('sha512').update(content).digest('hex');
  const hashTime = Date.now() - hashStart;

  // Encrypt the content
  const encryptionStart = Date.now();
  const encrypted = await encrypt(hash, algorithm, keys, mode, blockMode, streamMode);
  const encryptionTime = Date.now() - encryptionStart;

  // Decrypt the content
  const decryptionStart = Date.now();
  const decrypted = await decrypt(hash, encrypted, algorithm, keys, mode, blockMode, streamMode);
  const decryptionTime = Date.now() - decryptionStart;

  // Calculate metrics
  const entropy = calculateEntropy(encrypted.ciphertext || encrypted.signature);
  const avalanche = calculateAvalanche(content, encrypted.ciphertext || encrypted.signature);

  // Generate QR code
  const qrCode = `data:image/png;base64,${Buffer.from(encrypted.signature ? encrypted.signature : encrypted.ciphertext).toString('base64')}`;

  return {
    filename,
    file_size_mb: stats.size / (1024 * 1024),
    private_key: keys.privateKey ? Buffer.from(keys.privateKey) : null,
    public_key: keys.publicKey ? Buffer.from(keys.publicKey) : null,
    algorithm,
    mode,
    block_mode: blockMode,
    stream_mode: streamMode,
    original_size: content.length,
    hash,
    hash_time: hashTime,
    message_digest: hash,
    avalanche,
    encryption: encrypted.signature ? Buffer.from(encrypted.signature) : Buffer.from(encrypted.ciphertext),
    encrypt_time: encryptionTime,
    encrypted_size: encrypted.signature ? encrypted.signature.length : encrypted.ciphertext.length,
    entropy,
    ciphertext: encrypted.signature ? Buffer.from(JSON.stringify(encrypted)) : Buffer.from(encrypted.ciphertext),
    decryption: Buffer.from(decrypted),
    decrypt_time: decryptionTime,
    decrypted_size: decrypted.length,
    verified: decrypted === hash ? 'Valid' : 'Invalid',
    qr_code: qrCode,
    total_process_time: Date.now() - startTotalTime,
    file_load_time: encryptionStart - startTotalTime
  };
}

// Key generation
function generateKeys(algorithm) {
  switch (algorithm) {
    case 'RSA':
      const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 4096,
        publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs1', format: 'pem' }
      });
      return { publicKey, privateKey };

    case 'ECDSA':
      const ecdsaKeyPair = crypto.generateKeyPairSync('ec', {
        namedCurve: 'secp521r1',
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
      });
      return { 
        publicKey: ecdsaKeyPair.publicKey, 
        privateKey: ecdsaKeyPair.privateKey 
      };

    case 'RSA + ECDSA':
      const rsaKeyPair = crypto.generateKeyPairSync('rsa', {
        modulusLength: 4096,
        publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs1', format: 'pem' }
      });
      
      const ecdsaKeyPair2 = crypto.generateKeyPairSync('ec', {
        namedCurve: 'secp521r1',
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
      });
      
      return {
        publicKey: null,
        privateKey: null,
        rsaPublicKey: rsaKeyPair.publicKey,
        rsaPrivateKey: rsaKeyPair.privateKey,
        ecdsaPublicKey: ecdsaKeyPair2.publicKey,
        ecdsaPrivateKey: ecdsaKeyPair2.privateKey
      };

    case 'AES':
      return { 
        publicKey: null,
        privateKey: crypto.randomBytes(32).toString('hex') 
      };

    default:
      throw new Error(`Unsupported algorithm: ${algorithm}`);
  }
}
// Encryption
async function encrypt(content, algorithm, keys, mode, blockMode, streamMode) {
  try {
    switch (algorithm) {
      case 'RSA':
        const encrypted = crypto.publicEncrypt({
          key: keys.publicKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: 'sha512'
        }, Buffer.from(content));
        return { ciphertext: encrypted.toString('base64') };

      case 'ECDSA':
        const sign = crypto.createSign('sha512');
        sign.update(content);
        const signature = sign.sign(keys.privateKey, 'base64');
        return { signature };

      case 'RSA + ECDSA':
        // First encrypt with RSA
        const rsaEncrypted = crypto.publicEncrypt({
          key: keys.rsaPublicKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: 'sha512'
        }, Buffer.from(content));
        
        // Then sign with ECDSA
        const ecdsaSign = crypto.createSign('sha512');
        ecdsaSign.update(rsaEncrypted);
        const ecdsaSignature = ecdsaSign.sign(keys.ecdsaPrivateKey);
        
        return {
          encrypted: rsaEncrypted,
          signature: ecdsaSignature
        };

      case 'AES':
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv(
          `aes-256-${blockMode || 'cbc'}`,
          Buffer.from(keys.privateKey, 'hex'),
          iv
        );
        let ciphertext = cipher.update(content, 'utf8', 'base64');
        ciphertext += cipher.final('base64');
        return { 
          ciphertext: Buffer.concat([iv, Buffer.from(ciphertext, 'base64')]).toString('base64') 
        };

      default:
        throw new Error(`Unsupported encryption algorithm: ${algorithm}`);
    }
  } catch (error) {
    console.error('Encryption failed:', error);
    throw error;
  }
}

// Decryption
async function decrypt(original, encryptedData, algorithm, keys, mode, blockMode, streamMode) {
  try {
    switch (algorithm) {
      case 'RSA':
        const rsaDecrypted = crypto.privateDecrypt({
          key: keys.privateKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: 'sha512'
        }, Buffer.from(encryptedData.ciphertext, 'base64'));
        return rsaDecrypted.toString();

      case 'ECDSA':
        const verify = crypto.createVerify('sha512');
        verify.update(original);
        const isValid = verify.verify(keys.publicKey, Buffer.from(encryptedData.signature, 'base64'));
        return isValid ? original : 'INVALID_SIGNATURE';

      case 'RSA + ECDSA':
        // First verify the signature
        const verifySig = crypto.createVerify('sha512');
        verifySig.update(encryptedData.encrypted);
        const sigValid = verifySig.verify(keys.ecdsaPublicKey, encryptedData.signature);
        
        if (!sigValid) {
          return "INVALID_SIGNATURE";
        }
        
        // Then decrypt with RSA
        const rsaDecryptedContent = crypto.privateDecrypt({
          key: keys.rsaPrivateKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: 'sha512'
        }, encryptedData.encrypted);
        
        return rsaDecryptedContent.toString();

      case 'AES':
        const data = Buffer.from(encryptedData.ciphertext, 'base64');
        const iv = data.slice(0, 16);
        const ciphertext = data.slice(16);
        const decipher = crypto.createDecipheriv(
          `aes-256-${blockMode || 'cbc'}`,
          Buffer.from(keys.privateKey, 'hex'),
          iv
        );
        let aesDecrypted = decipher.update(ciphertext, null, 'utf8');
        aesDecrypted += decipher.final('utf8');
        return aesDecrypted;

      default:
        throw new Error(`Unsupported decryption algorithm: ${algorithm}`);
    }
  } catch (error) {
    console.error('Decryption failed:', error);
    throw error;
  }
}

// Metrics calculations
function calculateEntropy(data) {
  const len = data.length;
  const freq = {};
  for (const char of data) {
    freq[char] = (freq[char] || 0) + 1;
  }
  return Object.values(freq).reduce((sum, count) => {
    const p = count / len;
    return sum - (p * Math.log2(p));
  }, 0);
}

function calculateAvalanche(original, encrypted) {
  const maxLength = Math.min(original.length, encrypted.length);
  let diffBits = 0;
  let totalBits = 0;

  for (let i = 0; i < maxLength; i++) {
    const orig = original.charCodeAt(i).toString(2).padStart(8, '0');
    const encr = encrypted.charCodeAt(i).toString(2).padStart(8, '0');
    totalBits += 8;
    for (let j = 0; j < 8; j++) {
      if (orig[j] !== encr[j]) diffBits++;
    }
  }

  return totalBits > 0 ? (diffBits / totalBits) * 100 : 0;
}

// Database operations
async function storeResultInDatabase(result) {
  const connection = await pool.getConnection();
  try {
    await connection.query(`
      INSERT INTO digital_signatures (
        filename, file_size_mb, private_key, public_key, algorithm, mode,
        block_mode, stream_mode, original_size, hash, hash_time, message_digest,
        avalanche, encryption, encrypt_time, encrypted_size, entropy, ciphertext,
        decryption, decrypt_time, decrypted_size, verified, qr_code, total_process_time, file_load_time
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      result.filename,
      result.file_size_mb,
      result.private_key,
      result.public_key,
      result.algorithm,
      result.mode,
      result.block_mode,
      result.stream_mode,
      result.original_size,
      result.hash,
      result.hash_time,
      result.message_digest,
      result.avalanche,
      result.encryption,
      result.encrypt_time,
      result.encrypted_size,
      result.entropy,
      result.ciphertext,
      result.decryption,
      result.decrypt_time,
      result.decrypted_size,
      result.verified,
      result.qr_code,
      result.total_process_time,
      result.file_load_time
    ]);
  } catch (error) {
    console.error('Database error:', error);
    throw error;
  } finally {
    connection.release();
  }
}

// Main execution
(async () => {
  try {
    // Verify database schema first
    await verifyDatabaseSchema();
    
    // Process files
    const results = await processFilesFromFolder(
      './hash_sha512',  // Path to your input files
      'RSA',           // Algorithm (RSA, ECDSA, AES, RSA + ECDSA)
      'Block',         // Mode
      'cbc'           // Block mode (for block ciphers)
    );

    console.log('Processing completed successfully');
    console.log(`Processed ${results.length} files`);
  } catch (error) {
    console.error('Fatal error:', error);
    process.exit(1);
  } finally {
    await pool.end();
    process.exit(0);
  }
})();