import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public final class CryptoEngineTest {
    private static final byte[] PLAINTEXT =
            "test vault plaintext".getBytes(StandardCharsets.UTF_8);

    private static final char[] CORRECT_PASSWORD =
            "correct master password".toCharArray();

    private static final char[] WRONG_PASSWORD =
            "wrong master password".toCharArray();

    // VP1 (3) + version (1) + salt (16) + iterations (4) + nonce (12)
    private static final int HEADER_LENGTH = 3 + 1 + 16 + Integer.BYTES + 12;
    private static final int SALT_OFFSET = 3 + 1;

    private CryptoEngineTest() {
    }

    public static void main(String[] args) {
        run("correct password decrypts original plaintext", () -> {
            byte[] vault = CryptoEngine.encrypt(PLAINTEXT, CORRECT_PASSWORD);
            byte[] decrypted = CryptoEngine.decrypt(vault, CORRECT_PASSWORD);
            return Arrays.equals(PLAINTEXT, decrypted);
        });

        run("wrong password is rejected", () -> {
            byte[] vault = CryptoEngine.encrypt(PLAINTEXT, CORRECT_PASSWORD);
            return failsToDecrypt(vault, WRONG_PASSWORD);
        });

        run("modified salt/header is rejected", () -> {
            byte[] vault = CryptoEngine.encrypt(PLAINTEXT, CORRECT_PASSWORD);
            byte[] modified = Arrays.copyOf(vault, vault.length);

            modified[SALT_OFFSET] ^= 0x01;
            return failsToDecrypt(modified, CORRECT_PASSWORD);
        });

        run("modified ciphertext or tag is rejected", () -> {
            byte[] vault = CryptoEngine.encrypt(PLAINTEXT, CORRECT_PASSWORD);
            byte[] modified = Arrays.copyOf(vault, vault.length);

            // First byte after the authenticated header is ciphertext.
            modified[HEADER_LENGTH] ^= 0x01;
            return failsToDecrypt(modified, CORRECT_PASSWORD);
        });

        run("same plaintext encrypts to different vault bytes", () -> {
            byte[] first = CryptoEngine.encrypt(PLAINTEXT, CORRECT_PASSWORD);
            byte[] second = CryptoEngine.encrypt(PLAINTEXT, CORRECT_PASSWORD);
            return !Arrays.equals(first, second);
        });
    }

    private static boolean failsToDecrypt(byte[] vault, char[] password) {
        try {
            CryptoEngine.decrypt(vault, password);
            return false;
        } catch (CryptoEngine.InvalidVaultException expected) {
            return true;
        }
    }

    private static void run(String name, TestCase test) {
        try {
            if (test.run()) {
                System.out.println("PASS: " + name);
            } else {
                System.out.println("FAIL: " + name);
            }
        } catch (Exception e) {
            System.out.println("FAIL: " + name);
        }
    }

    @FunctionalInterface
    private interface TestCase {
        boolean run() throws Exception;
    }
}