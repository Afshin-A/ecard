// Helper function to convert Uint8Array to base64
function uint8ArrayToBase64(bytes) {
  const chunkSize = 0x8000; // Process 32KB chunks to avoid argument limits
  let binary = '';
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.subarray(i, i + chunkSize);
    binary += String.fromCharCode(...chunk);
  }
  return btoa(binary);
}

// Function to derive a 256-bit key using PBKDF2
async function deriveKey(password, salt) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 1000,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-CBC', length: 256 },
    false,
    ['decrypt']
  );
}

// Function to decrypt a file and return the decrypted bytes
async function decryptFile(encryptedData, password) {
  const salt = new Uint8Array(encryptedData.slice(0, 16)); // First 16 bytes: salt
  const iv = new Uint8Array(encryptedData.slice(16, 32)); // Next 16 bytes: IV
  const ciphertext = encryptedData.slice(32); // Remaining bytes: ciphertext

  const key = await deriveKey(password, salt);
  try {
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-CBC', iv },
      key,
      ciphertext
    );
    return new Uint8Array(decrypted);
  } catch (error) {
    throw new Error('Decryption failed: ' + error.message);
  }
}

// Function to validate password by decrypting a test image
async function validatePassword(password) {
  try {
    const response = await fetch('encrypted/test.jpg.enc');
    if (!response.ok) throw new Error('Failed to fetch test image');
    const encryptedData = await response.arrayBuffer();

    // Decrypt test image
    const decryptedBytes = await decryptFile(encryptedData, password);

    // Convert to base64 and test if it's a valid image
    const base64 = uint8ArrayToBase64(decryptedBytes);
    const dataUrl = `data:image/jpeg;base64,${base64}`;

    // Create an image to validate
    return new Promise((resolve, reject) => {
      const img = new Image();
      img.onload = () => resolve(true); // Valid image
      img.onerror = () => reject(new Error('Invalid password or corrupted test image'));
      img.src = dataUrl;
    });
  } catch (error) {
    throw new Error('Password validation failed: ' + error.message);
  }
}

// Main function to load and decrypt photos
async function loadPhotos() {
  const password = document.getElementById('password').value;
  const passwordOverlay = document.getElementById('password-overlay');
  const loadingSpinner = document.getElementById('loading-spinner');
  const card = document.querySelector('.card');
  const photoImages = document.querySelectorAll('.photo img');

  // Show loading spinner, hide password input
  passwordOverlay.querySelector('#password-container').style.display = 'none';
  loadingSpinner.style.display = 'block';

  try {
    // Validate password with test image
    await validatePassword(password);

    // Password is valid, show main content
    passwordOverlay.style.display = 'none';
    card.style.display = 'block';

    // Map encrypted files to photo <img> elements
 const photoFiles = [
        'encrypted/1.jpg.enc',
        'encrypted/2.jpg.enc', 
        'encrypted/3.jpg.enc',
        'encrypted/4.jpg.enc',
        'encrypted/5.jpg.enc',
        'encrypted/6.jpg.enc',
        'encrypted/7.jpg.enc',
        'encrypted/8.jpg.enc',
        'encrypted/9.jpg.enc',
        'encrypted/10.jpg.enc'
    ];

    if (photoFiles.length !== photoImages.length) {
      throw new Error('Number of encrypted files does not match number of <img> elements');
    }

    // Decrypt and set src for each photo
    for (let i = 0; i < photoFiles.length; i++) {
      try {
        const response = await fetch(photoFiles[i]);
        if (!response.ok) throw new Error(`Failed to fetch ${photoFiles[i]}`);
        const encryptedData = await response.arrayBuffer();

        // Decrypt photo
        const decryptedBytes = await decryptFile(encryptedData, password);

        // Convert to base64 and set img src
        const base64 = uint8ArrayToBase64(decryptedBytes);
        photoImages[i].src = `data:image/jpeg;base64,${base64}`;
      } catch (error) {
        console.error(`Error processing ${photoFiles[i]}:`, error);
        photoImages[i].alt = `Failed to load photo: ${error.message}`;
      }
    }
  } catch (error) {
    console.error('Validation error:', error);
    // Hide spinner, show password input with error
    loadingSpinner.style.display = 'none';
    passwordOverlay.querySelector('#password-container').style.display = 'block';
    const errorMsg = document.createElement('p');
    errorMsg.textContent = error.message;
    errorMsg.style.color = 'red';
    passwordOverlay.querySelector('#password-container').appendChild(errorMsg);
  }
}