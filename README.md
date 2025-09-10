# A Private Love Letter in Public (via Symmetric Encryption)
This is an open source project that is publicly hosted via GitHub Pages. It is purely written in Javascript, HTML, and CSS (via the scss preprocessor); it does not utilize a backend server or any external API calls. 
However, it is also a personal project that contains private information and pictures. 
Consequently, we require some sort of authentication to prevent the public from unauthorized access.
## The Solution
Instead of uploadding raw picture files, we first pass them through a symmetric encryption algorithm using a secret key only known to us and the intended card recepient. We would then upload the encrypted files to GitHub instead.
To view the card, the user will be prompted for a password. This password will be used to decrypt a test image file, which, if successful, will yield a valid file the browser can display. That is our authentication condition. 

## The Details
To encrypt and decrypt our files, we use the Web Crypto API: it is fast, light weight, and supported by all major browsers across a variety of devices. First, we input our secret key (i.e. the password) and a random salt value into the pbkdf2 algorithm to create a 256 bit long secret key.
Next, this key along with the initialization vector are used to create an AES cipher. 

Since this is a symmetric algorithm, the decryption process is very similar and uses the same key. However, this time we use the user input to test if decryption is successful. If so, the user has entered the correct password and may proceed to view the contents of the card.


Note that this approach to authentication is rudimentary and should not be used in sensitive applications: it is still vulnerable to bruteforce attacks and relies on the strengh of the user password used.

For a more comprehensive overview of how AES works, please visit [this article](https://crypto.stackexchange.com/a/29135) by GeeksforGeeks.

Credits for the 3D e-card design are attributed to [Regis Gaughan](https://dev.to/rgthree).
