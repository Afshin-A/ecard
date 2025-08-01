const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
require('dotenv').config();

const inputDir = path.join(__dirname, 'media/pictures');
const outputDir = path.join(__dirname, 'encrypted');

const algorithm = 'aes-256-cbc';
const secretKey = process.env.SECRET_KEY
const saltLength = 16; 
const ivLength = 16;
const pbkdf2Iterations = 1000;

if (!secretKey) {
  console.error('Error: SECRET_KEY not found in .env file');
  process.exit(1);
}

if (!fs.existsSync(outputDir)) {
  fs.mkdirSync(outputDir);
}

fs.readdir(inputDir, (err, files) => {
  // display error opening dir
  if (err) {
    console.error('Error reading input directory:', err);
    process.exit(1);
  }
  // filter all image files
  const imageFiles = files.filter(file => /\.(jpg|jpeg|png|gif)$/i.test(file));
  // if no image files, throw error
  if (imageFiles.length === 0) {
    console.log('No image files found in', inputDir);
    process.exit(0);
  }

  // for each image file
  imageFiles.forEach(file => {
    const inputPath = path.join(inputDir, file);
    const outputPath = path.join(outputDir, `${file}.enc`);

    const salt = crypto.randomBytes(saltLength);
    const iv = crypto.randomBytes(ivLength);
    // using secret key to generate a 256 bit long key used in aes 
    const key = crypto.pbkdf2Sync(secretKey, salt, pbkdf2Iterations, 32, 'sha256');
    // create the cipher
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    
    // stream for read input file
    const input = fs.createReadStream(inputPath);
    // stream for writing encrypted output file
    const output = fs.createWriteStream(outputPath);
    
    // prepending salt and iv to output file
    // to be used later for decryption
    output.write(salt);
    output.write(iv);

    // connects the input stream (file data) to the cipher, then to the output stream
    // input stream reads chunks of the file’s data 
    // each chunk is then fed into the aes cipher we created
    // the cipher outputs encrypted chunks (ciphertext), which are written to the output stream.
    input.pipe(cipher).pipe(output);

    output.on('finish', () => {
      console.log(`Encrypted ${file} to ${outputPath}`);
    });

    output.on('error', err => {
      console.error(`Error encrypting ${file}:`, err);
    });

  });
});
