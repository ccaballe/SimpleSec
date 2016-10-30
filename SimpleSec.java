import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Scanner;

public class SimpleSec {

    public static void main(String[] args) {
        Scanner in = new Scanner(System.in);
        RSALibrary rsaLibrary = new RSALibrary();
        String command = args[0];
        switch (command) {
            case "g":
                System.out.println("Enter a passphrase (16 bytes) to protect the private key.");
                String passphrase = in.next();
                try {
                    rsaLibrary.generateKeys(passphrase);
                } catch (IOException e) {
                    e.printStackTrace();
                }
                break;
            case "e":
                String sourceFile = args[1];
                String destFile = args[2];
                try {
                    byte[] plainText = Files.readAllBytes(Paths.get(sourceFile));
                    byte[] sessionKey = new byte[16];
                    SecureRandom.getInstanceStrong().nextBytes(sessionKey);
                    SymmetricCipher symmetricCipher = new SymmetricCipher(sessionKey);
                    byte[] ciphertext = symmetricCipher.encryptCBC(plainText);
                    Files.write(Paths.get(destFile), ciphertext);

                    // ciframos clave de sesión con clave pública
                    ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream(rsaLibrary.PUBLIC_KEY_FILE));
                    PublicKey publicKey = (PublicKey) inputStream.readObject();
                    byte[] publicKeyEncrypted = rsaLibrary.encrypt(sessionKey, publicKey);
                    Files.write(Paths.get(destFile), publicKeyEncrypted, StandardOpenOption.APPEND);

                    // firma
                    PrivateKey privateKey = getPrivateKey(rsaLibrary);
                    // TODO: Firmar un hash!
                    byte[] sign = rsaLibrary.sign(ciphertext, privateKey);
                    Files.write(Paths.get(destFile), sign, StandardOpenOption.APPEND);

                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (ClassNotFoundException e) {
                    e.printStackTrace();
                }

                break;
            case "d":
                sourceFile = args[1];
                destFile = args[2];
                try {
                    int signSize = rsaLibrary.keySize / 8;
                    byte[] fileCiphered = Files.readAllBytes(Paths.get(sourceFile));
                    byte[] ciphertext = Arrays.copyOfRange(fileCiphered, 0, fileCiphered.length - (signSize * 2));
                    byte[] sessionKeyCiphered = Arrays.copyOfRange(fileCiphered, fileCiphered.length - (signSize * 2), fileCiphered.length - signSize);
                    byte[] sign = Arrays.copyOfRange(fileCiphered, fileCiphered.length - (signSize), fileCiphered.length);
                    PublicKey publicKey = getPublicKey(rsaLibrary);
                    boolean isVerified = rsaLibrary.verify(ciphertext, sign, publicKey);
                    if (!isVerified) {
                        System.err.println("Sign can not be verified. Sign is wrong");
                        System.exit(-1);
                    }
                    PrivateKey privateKey = getPrivateKey(rsaLibrary);
                    byte[] sessionKey = rsaLibrary.decrypt(sessionKeyCiphered, privateKey);
                    SymmetricCipher symmetricCipher = new SymmetricCipher(sessionKey);
                    byte[] plaintext = symmetricCipher.decryptCBC(ciphertext);
                    Files.write(Paths.get(destFile), plaintext);

                } catch (IOException e) {
                    e.printStackTrace();
                } catch (InvalidPaddingException e) {
                    e.printStackTrace();
                }

                break;
            default:
                System.out.println("Unknown operation");
                break;
        }

    }

    private static PrivateKey getPrivateKey(RSALibrary rsaLibrary) {
        Scanner in = new Scanner(System.in);
        System.out.println("Enter a passphrase (16 bytes) to get the private key.");
        String passphrase = in.next();
        PrivateKey privateKey = null;
        try {
            byte[] privateKeyBytes = Files.readAllBytes(Paths.get(rsaLibrary.PRIVATE_KEY_FILE));
            SymmetricCipher symmetricCipher = new SymmetricCipher(passphrase.getBytes());
            privateKeyBytes = symmetricCipher.decryptCBC(privateKeyBytes);
            ByteArrayInputStream bis = new ByteArrayInputStream(privateKeyBytes);
            privateKey = (PrivateKey) new ObjectInputStream(bis).readObject();

        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            System.err.println("Cannot access to private key");
        }
        return privateKey;
    }

    private static PublicKey getPublicKey(RSALibrary rsaLibrary) {
        ObjectInputStream inputStream = null;
        PublicKey publicKey = null;
        try {
            inputStream = new ObjectInputStream(new FileInputStream(rsaLibrary.PUBLIC_KEY_FILE));

            publicKey = (PublicKey) inputStream.readObject();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
        return publicKey;
    }
}
