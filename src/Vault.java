import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

public final class Vault {
    private static final int PLAINTEXT_MAGIC = 0x564C5431; // "VLT1"
    private static final int MAX_ENTRIES = 100_000;
    private static final int MAX_FIELD_BYTES = 1_048_576; // 1 MiB

    private final Map<String, String> entries;
    private final char[] masterPassword;

    public Vault(char[] masterPassword) {
        requireMasterPassword(masterPassword);
        this.masterPassword = masterPassword.clone();
        this.entries = new LinkedHashMap<>();
    }

    private Vault(char[] masterPassword, Map<String, String> entries) {
        requireMasterPassword(masterPassword);
        this.masterPassword = masterPassword.clone();
        this.entries = entries;
    }

    public void set(String service, String password) {
        requireService(service);

        if (password == null) {
            throw new IllegalArgumentException("Password must be a string.");
        }

        entries.put(service, password);
    }

    public String get(String service) {
        requireService(service);
        return entries.get(service);
    }

    public boolean remove(String service) {
        requireService(service);
        return entries.remove(service) != null;
    }

    /*
     * Returns a copy because callers should not receive the Vault's internal
     * master-password array. After passing this copy to CryptoEngine, the
     * caller can erase it with Arrays.fill(copy, '\0').
     */
    public char[] masterPasswordCopy() {
        return masterPassword.clone();
    }

    /*
     * Call this before discarding a Vault after create/load replacement or a
     * failed load. It reduces how long the old password remains in memory.
     */
    public void clearMasterPassword() {
        Arrays.fill(masterPassword, '\0');
    }

    /*
     * Plaintext format, subsequently encrypted by CryptoEngine:
     *
     * VLT1 magic (4 bytes) | entry count (4 bytes) |
     *   repeated: service UTF-8 length (4 bytes) | service UTF-8 bytes |
     *             password UTF-8 length (4 bytes) | password UTF-8 bytes
     */
    public byte[] serialize() {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(bytes);

            out.writeInt(PLAINTEXT_MAGIC);
            out.writeInt(entries.size());

            for (Map.Entry<String, String> entry : entries.entrySet()) {
                writeString(out, entry.getKey());
                writeString(out, entry.getValue());
            }

            out.flush();
            return bytes.toByteArray();

        } catch (IOException e) {
            // ByteArrayOutputStream does not normally throw IOException.
            throw new IllegalStateException("Could not serialize vault.", e);
        }
    }

    public static Vault deserialize(byte[] plaintext, char[] masterPassword) {
        requireMasterPassword(masterPassword);

        if (plaintext == null) {
            throw new IllegalArgumentException("Vault plaintext is missing.");
        }

        try {
            DataInputStream in = new DataInputStream(
                    new ByteArrayInputStream(plaintext)
            );

            if (in.readInt() != PLAINTEXT_MAGIC) {
                throw new IllegalArgumentException("Invalid vault plaintext.");
            }

            int count = in.readInt();
            if (count < 0 || count > MAX_ENTRIES) {
                throw new IllegalArgumentException("Invalid vault entry count.");
            }

            Map<String, String> entries = new LinkedHashMap<>();

            for (int i = 0; i < count; i++) {
                String service = readString(in);
                String password = readString(in);

                if (service.isEmpty() || entries.containsKey(service)) {
                    throw new IllegalArgumentException("Invalid vault entries.");
                }

                entries.put(service, password);
            }

            // No unexplained trailing bytes are accepted.
            if (in.available() != 0) {
                throw new IllegalArgumentException("Invalid vault plaintext.");
            }

            return new Vault(masterPassword, entries);

        } catch (IOException | IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid vault plaintext.", e);
        }
    }

    private static void writeString(DataOutputStream out, String value)
            throws IOException {
        byte[] utf8 = value.getBytes(StandardCharsets.UTF_8);

        if (utf8.length > MAX_FIELD_BYTES) {
            throw new IllegalArgumentException("Vault field is too large.");
        }

        out.writeInt(utf8.length);
        out.write(utf8);
    }

    private static String readString(DataInputStream in) throws IOException {
        int length = in.readInt();

        if (length < 0 || length > MAX_FIELD_BYTES || length > in.available()) {
            throw new IllegalArgumentException("Invalid vault field length.");
        }

        byte[] utf8 = new byte[length];
        in.readFully(utf8);
        return new String(utf8, StandardCharsets.UTF_8);
    }

    private static void requireMasterPassword(char[] masterPassword) {
        if (masterPassword == null || masterPassword.length == 0) {
            throw new IllegalArgumentException(
                    "Master password must not be empty."
            );
        }
    }

    private static void requireService(String service) {
        if (service == null || service.isEmpty()) {
            throw new IllegalArgumentException(
                    "Service name must not be empty."
            );
        }
    }
}