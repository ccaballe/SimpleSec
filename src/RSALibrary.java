import javax.crypto.Cipher;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;


public class RSALibrary {

    // String to hold name of the encryption algorithm.
    public final String ALGORITHM = "RSA";

    //String to hold the name of the private key file.
    public final String PRIVATE_KEY_FILE = "./private.key";

    // String to hold name of the public key file.
    public final String PUBLIC_KEY_FILE = "./public.key";

    int keySize = 1024;


    /***********************************************************************************/
   /* Generates an RSA key pair (a public and a private key) of 1024 bits length */
   /* Stores the keys in the files defined by PUBLIC_KEY_FILE and PRIVATE_KEY_FILE */
   /* Throws IOException */

    /***********************************************************************************/
    public void generateKeys(String passphrase) throws IOException {

        try {

            final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
            keyGen.initialize(keySize);

            // Use KeyGen to generate a public and a private key
            KeyPair keyPair = keyGen.generateKeyPair();
            // Store the public key in the file PUBLIC_KEY_FILE
            PublicKey publicKey = keyPair.getPublic();
            writePublicKeyInFile(publicKey, PUBLIC_KEY_FILE);
            // Store the private key in the file PRIVATE_KEY_FILE
            PrivateKey privateKey = keyPair.getPrivate();
            writePrivateKeyInFile(privateKey, PRIVATE_KEY_FILE, passphrase);

        } catch (NoSuchAlgorithmException e) {
            System.out.println("Exception: " + e.getMessage());
            System.exit(-1);
        }
    }

    private void writePublicKeyInFile(PublicKey publicKey, String file) {
        try {
            ObjectOutputStream keyOs = new ObjectOutputStream(new FileOutputStream(file));
            keyOs.writeObject(publicKey);
            keyOs.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void writePrivateKeyInFile(PrivateKey key, String file, String passphrase) {
        try {
            SymmetricCipher symmetricCipher = new SymmetricCipher(passphrase.getBytes());
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutput out = new ObjectOutputStream(bos);
            out.writeObject(key);
            out.flush();
            byte[] privateKeyBytes = bos.toByteArray();
            byte[] privateKeyProtected = symmetricCipher.encryptCBC(privateKeyBytes);
            Files.write(Paths.get(file), privateKeyProtected);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            System.err.println("Invalid passphrase length. It must be 16 bytes");
        }

    }

    /***********************************************************************************/
  /* Encrypts a plaintext using an RSA public key. */
  /* Arguments: the plaintext and the RSA public key */
  /* Returns a byte array with the ciphertext */

    /***********************************************************************************/
    public byte[] encrypt(byte[] plaintext, PublicKey key) {

        byte[] ciphertext = null;

        // Gets an RSA cipher object
        final Cipher cipher;
        try {
            cipher = Cipher.getInstance(ALGORITHM);
            // Initialize the cipher object and use it to encrypt the plaintext
            cipher.init(Cipher.ENCRYPT_MODE, key);
            ciphertext = cipher.doFinal(plaintext);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return ciphertext;
    }


    /***********************************************************************************/
  /* Decrypts a ciphertext using an RSA private key. */
  /* Arguments: the ciphertext and the RSA private key */
  /* Returns a byte array with the plaintext */

    /***********************************************************************************/
    public byte[] decrypt(byte[] ciphertext, PrivateKey key) {

        byte[] plaintext = null;

        try {
            // Gets an RSA cipher object
            final Cipher cipher = Cipher.getInstance(ALGORITHM);

            // Initialize the cipher object and use it to decrypt the ciphertext
            cipher.init(Cipher.DECRYPT_MODE, key);
            plaintext = cipher.doFinal(ciphertext);

        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return plaintext;
    }

    /***********************************************************************************/
  /* Signs a plaintext using an RSA private key. */
  /* Arguments: the plaintext and the RSA private key */
  /* Returns a byte array with the signature */

    /***********************************************************************************/
    public byte[] sign(byte[] plaintext, PrivateKey key) {

        byte[] signedInfo = null;

        try {
            // Gets a Signature object
            Signature signature = Signature.getInstance("SHA1withRSA");
            // Initialize the signature object with the private key
            signature.initSign(key);
            // Set plaintext as the bytes to be signed
            signature.update(plaintext);
            // Sign the plaintext and obtain the signature (signedInfo)
            signedInfo = signature.sign();
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return signedInfo;
    }

    /***********************************************************************************/
  /* Verifies a signature over a plaintext */
  /* Arguments: the plaintext, the signature to be verified (signed)
  /* and the RSA public key */
  /* Returns TRUE if the signature was verified, false if not */

    /***********************************************************************************/
    public boolean verify(byte[] plaintext, byte[] signed, PublicKey key) {

        boolean result = false;

        try {
            // Gets a Signature object
            Signature signature = Signature.getInstance("SHA1withRSA");
            // Initialize the signature oject with the public key
            signature.initVerify(key);
            // Set plaintext as the bytes to be veryfied
            signature.update(plaintext);
            // Verify the signature (signed). Store the outcome in the boolean result
            result = signature.verify(signed);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return result;
    }
}

