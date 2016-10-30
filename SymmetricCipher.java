import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.security.InvalidKeyException;
import java.util.Arrays;

public class SymmetricCipher {

    SymmetricEncryption s;

    // Initialization Vector (fixed)

    byte[] iv = new byte[]{(byte) 49, (byte) 50, (byte) 51, (byte) 52, (byte) 53, (byte) 54,
            (byte) 55, (byte) 56, (byte) 57, (byte) 48, (byte) 49, (byte) 50, (byte) 51, (byte) 52,
            (byte) 53, (byte) 54};

    /*************************************************************************************/
    /* Constructor method */

    /*************************************************************************************/
    public SymmetricCipher(byte[] byteKey) {
        try {
            this.s = new SymmetricEncryption(byteKey);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    /*************************************************************************************/
    /* Method to encrypt using AES/CBC/PKCS5 */

    /*************************************************************************************/
    public byte[] encryptCBC(byte[] input) {

        byte[] ciphertext;

        // Generate the plaintext with padding
        int nPadding = s.AES_BLOCK_SIZE - (input.length % s.AES_BLOCK_SIZE);
        byte[] withPadding = textWithPadding(input, nPadding);

        // Generate the ciphertext
        ciphertext = getCiphertext(withPadding);

        return ciphertext;
    }

    /*************************************************************************************/
    /* Method to decrypt using AES/CBC/PKCS5 */

    /*************************************************************************************/


    public byte[] decryptCBC(byte[] input) throws InvalidPaddingException {


        byte[] finalplaintext;

        // Generate the plaintext
        byte[] plaintextWithPadding = getPlaintext(input);

        // Eliminate the padding
        int nPadding = 0;
        nPadding = getPadding(plaintextWithPadding);

        finalplaintext = textWithoutPadding(plaintextWithPadding, nPadding);

        return finalplaintext;
    }

    private int getPadding(byte[] input) throws InvalidPaddingException {
        byte[] lastBlock = new byte[s.AES_BLOCK_SIZE];
        System.arraycopy(input, input.length - s.AES_BLOCK_SIZE, lastBlock, 0, s.AES_BLOCK_SIZE);

        for (int i = 1; i <= s.AES_BLOCK_SIZE; i++) {
            byte[] checkPadding = new byte[i];
            for (int j = 1; j <= i; j++) {
                checkPadding[j - 1] = (byte) i;
            }

            byte[] bytesWithPadding = new byte[i];
            System.arraycopy(lastBlock, lastBlock.length - i, bytesWithPadding, 0, i);

            if (new String(bytesWithPadding).equals(new String(checkPadding)))
                return i;
        }
        throw new InvalidPaddingException("Cipher text has an invalid padding");
    }

    private byte[] getCiphertext(byte[] withPadding) {
        byte[] ciphertext = new byte[withPadding.length];

        try {
            byte[] ivRound = this.iv;
            for (int i = 0; i < withPadding.length; i += s.AES_BLOCK_SIZE) {
                byte[] cipherBlock = s.encryptBlock(xorBytes(Arrays.copyOfRange(withPadding, i, i + s.AES_BLOCK_SIZE), ivRound));
                System.arraycopy(cipherBlock, 0, ciphertext, i, s.AES_BLOCK_SIZE);
                ivRound = cipherBlock;
            }
            return ciphertext;
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
        return withPadding;
    }

    private byte[] getPlaintext(byte[] ciphertext) {
        byte[] plaintext = new byte[ciphertext.length];
        try {
            byte[] ivRound = this.iv;
            for (int i = 0; i < ciphertext.length; i += s.AES_BLOCK_SIZE) {
                byte[] cipherBlock = Arrays.copyOfRange(ciphertext, i, i + s.AES_BLOCK_SIZE);
                byte[] plainBlock = s.decryptBlock(cipherBlock);
                System.arraycopy(xorBytes(plainBlock, ivRound), 0, plaintext, i, s.AES_BLOCK_SIZE);
                ivRound = cipherBlock;
            }
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
        return plaintext;
    }

    private byte[] xorBytes(byte[] arr1, byte[] arr2) {
        byte[] res = new byte[arr1.length];
        for (int i = 0; i < arr1.length; i++) {
            int xor = (int) arr1[i] ^ (int) arr2[i];
            byte b = (byte) (0xff & xor);
            res[i] = b;
        }
        return res;
    }

    private byte[] textWithPadding(byte[] input, int nPadding) {
        byte[] withPadding;
        if (nPadding == 0) {
            withPadding = new byte[input.length + s.AES_BLOCK_SIZE];
            System.arraycopy(input, 0, withPadding, 0, input.length);
            for (int i = 0; i < s.AES_BLOCK_SIZE; i++) {
                withPadding[input.length + i] = (byte) s.AES_BLOCK_SIZE;
            }
        } else {
            withPadding = new byte[input.length + nPadding];
            System.arraycopy(input, 0, withPadding, 0, input.length);
            for (int i = 0; i < nPadding; i++) {
                withPadding[input.length + i] = (byte) nPadding;
            }
        }
        return withPadding;
    }

    private byte[] textWithoutPadding(byte[] input, int nPadding) {
        byte[] textWithoutPadding = new byte[input.length - nPadding];
        for (int i = 0; i < textWithoutPadding.length; i++) {
            textWithoutPadding[i] = input[i];
        }
        return textWithoutPadding;
    }
}

