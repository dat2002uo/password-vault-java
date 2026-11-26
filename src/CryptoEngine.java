import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public final class CryptoEngine {
    private static final byte[] MAGIC = {'V', 'P', '1'};
    private static final byte VERSION = 1;

    public static final int ITERATIONS = 600_000;
    private static final int MAX_ITERATIONS = 5_000_000;

    private static final int SALT_LENGTH = 16;
    private static final int NONCE_LENGTH = 12;
    private static final int KEY_LENGTH_BITS = 256;
    private static final int TAG_LENGTH_BITS = 128;
    private static final int TAG_LENGTH_BYTES = TAG_LENGTH_BITS / 8;

    private static final int VERSION_OFFSET = MAGIC.length;
    private static final int SALT_OFFSET = VERSION_OFFSET + 1;
    private static final int ITERATIONS_OFFSET = SALT_OFFSET + SALT_LENGTH;
    private static final int NONCE_OFFSET = ITERATIONS_OFFSET + Integer.BYTES;
    private static final int HEADER_LENGTH = NONCE_OFFSET + NONCE_LENGTH;

    private static final SecureRandom RANDOM = new SecureRandom();

    private CryptoEngine() {
    }

    /*
     * Output format:
     * magic | version | salt | iterations | nonce | ciphertext | tag
     *
     * The header through nonce is AES-GCM authenticated associated data.
     * Java's AES-GCM Cipher returns ciphertext followed by the 16-byte tag.
     */
    public static byte[] encrypt(byte[] plaintext, char[] masterPassword)
            throws CryptoException {
        requireMasterPassword(masterPassword);

        byte[] salt = new byte[SALT_LENGTH];
        byte[] nonce = new byte[NONCE_LENGTH];
        RANDOM.nextBytes(salt);
        RANDOM.nextBytes(nonce);

        byte[] header = createHeader(salt, ITERATIONS, nonce);
        byte[] keyBytes = null;

        try {
            keyBytes = deriveKey(masterPassword, salt, ITERATIONS);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(
                    Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(keyBytes, "AES"),
                    new GCMParameterSpec(TAG_LENGTH_BITS, nonce)
            );
            cipher.updateAAD(header);

            byte[] ciphertextAndTag = cipher.doFinal(plaintext);

            ByteBuffer result = ByteBuffer.allocate(
                    HEADER_LENGTH + ciphertextAndTag.length
            );
            result.put(header);
            result.put(ciphertextAndTag);
            return result.array();

        } catch (GeneralSecurityException e) {
            throw new CryptoException("Encryption failed.", e);
        } finally {
            if (keyBytes != null) {
                Arrays.fill(keyBytes, (byte) 0);
            }
        }
    }

    public static byte[] decrypt(byte[] vaultBytes, char[] masterPassword)
            throws InvalidVaultException {
        requireMasterPassword(masterPassword);

        if (vaultBytes == null || vaultBytes.length < HEADER_LENGTH + TAG_LENGTH_BYTES) {
            throw invalidVault();
        }

        byte[] header = Arrays.copyOfRange(vaultBytes, 0, HEADER_LENGTH);

        if (!Arrays.equals(
                Arrays.copyOfRange(header, 0, MAGIC.length), MAGIC)
                || header[VERSION_OFFSET] != VERSION) {
            throw invalidVault();
        }

        byte[] salt = Arrays.copyOfRange(
                header, SALT_OFFSET, SALT_OFFSET + SALT_LENGTH
        );

        int iterations = ByteBuffer.wrap(
                header, ITERATIONS_OFFSET, Integer.BYTES
        ).getInt();

        if (iterations <= 0 || iterations > MAX_ITERATIONS) {
            throw invalidVault();
        }

        byte[] nonce = Arrays.copyOfRange(
                header, NONCE_OFFSET, NONCE_OFFSET + NONCE_LENGTH
        );

        byte[] ciphertextAndTag = Arrays.copyOfRange(
                vaultBytes, HEADER_LENGTH, vaultBytes.length
        );

        byte[] keyBytes = null;
        try {
            keyBytes = deriveKey(masterPassword, salt, iterations);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(
                    Cipher.DECRYPT_MODE,
                    new SecretKeySpec(keyBytes, "AES"),
                    new GCMParameterSpec(TAG_LENGTH_BITS, nonce)
            );
            cipher.updateAAD(header);

            return cipher.doFinal(ciphertextAndTag);

        } catch (GeneralSecurityException e) {
            // Includes wrong password, changed header, ciphertext, or tag.
            throw invalidVault();
        } finally {
            if (keyBytes != null) {
                Arrays.fill(keyBytes, (byte) 0);
            }
        }
    }

    private static byte[] createHeader(byte[] salt, int iterations, byte[] nonce) {
        ByteBuffer header = ByteBuffer.allocate(HEADER_LENGTH);
        header.put(MAGIC);
        header.put(VERSION);
        header.put(salt);
        header.putInt(iterations);
        header.put(nonce);
        return header.array();
    }

    private static byte[] deriveKey(
            char[] masterPassword, byte[] salt, int iterations
    ) throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(
                masterPassword, salt, iterations, KEY_LENGTH_BITS
        );

        try {
            return SecretKeyFactory
                    .getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(spec)
                    .getEncoded();
        } finally {
            spec.clearPassword();
        }
    }

    private static void requireMasterPassword(char[] masterPassword) {
        if (masterPassword == null || masterPassword.length == 0) {
            throw new IllegalArgumentException("Master password must not be empty.");
        }
    }

    private static InvalidVaultException invalidVault() {
        return new InvalidVaultException("Invalid vault.");
    }

    public static class CryptoException extends Exception {
        public CryptoException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    public static final class InvalidVaultException extends Exception {
        public InvalidVaultException(String message) {
            super(message);
        }
    }
}