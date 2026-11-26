import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class VaultApp {
    static Vault activeVault = null;   // null = no vault

    public static void main(String[] args) throws IOException {
        BufferedReader in = new BufferedReader(
                new InputStreamReader(System.in, StandardCharsets.UTF_8)
        );
        BufferedWriter out = new BufferedWriter(
                new OutputStreamWriter(System.out, StandardCharsets.UTF_8)
        );
        String line;
        while ((line = in.readLine()) != null) {
            out.write(handle(line));
            out.newLine();
            out.flush();
        }
    }

    static String handle(String line) {
        Map<String, String> req = parseJson(line);
        if (req == null) return err("INVALID_INPUT");
        String op = req.get("op");
        if (op == null) return err("INVALID_INPUT");    // {} must not throw
        switch (op) {
            case "create": return doCreate(req);
            case "set":    return doSet(req);
            case "get":    return doGet(req);
            case "remove": return doRemove(req);
            case "dump":   return doDump();
            case "load":   return doLoad(req);
            default:       return err("INVALID_INPUT");
        }
    }

    static String doCreate(Map<String, String> req) {
        String mp = req.get("master_password");
        if (mp == null || mp.isEmpty()) return err("INVALID_INPUT");
        replaceVault(new Vault(mp.toCharArray()));
        return ok();
    }

    static String doSet(Map<String, String> req) {
        String svc = req.get("service");
        String pw  = req.get("password");
        if (svc == null || svc.isEmpty()) return err("INVALID_INPUT");
        if (pw == null) return err("INVALID_INPUT");    // "" is ok
        if (activeVault == null) return err("NO_VAULT");
        activeVault.set(svc, pw);
        return ok();
    }

    static String doGet(Map<String, String> req) {
        String svc = req.get("service");
        if (svc == null || svc.isEmpty()) return err("INVALID_INPUT");
        if (activeVault == null) return err("NO_VAULT");
        String pw = activeVault.get(svc);
        if (pw == null) return "{\"ok\":true,\"password\":null}";
        return "{\"ok\":true,\"password\":\"" + jsonEscape(pw) + "\"}";
    }

    static String doRemove(Map<String, String> req) {
        String svc = req.get("service");
        if (svc == null || svc.isEmpty()) return err("INVALID_INPUT");
        if (activeVault == null) return err("NO_VAULT");
        return "{\"ok\":true,\"removed\":" + activeVault.remove(svc) + "}";
    }

    static String doDump() {
        if (activeVault == null) return err("NO_VAULT");
        char[] passwordCopy = null;
        byte[] plaintext = null;
        byte[] encrypted = null;
        try {
            passwordCopy = activeVault.masterPasswordCopy();
            plaintext = activeVault.serialize();
            encrypted = CryptoEngine.encrypt(plaintext, passwordCopy);
            String base64 = Base64.getEncoder().encodeToString(encrypted);
            return "{\"ok\":true,\"data\":\"" + base64 + "\"}";
        } catch (CryptoEngine.CryptoException e) {
            // unreachable under a standard JDK; protocol has no suitable code
            System.err.println("Vault encryption failed.");
            return err("INTERNAL_ERROR");
        } finally {
            if (passwordCopy != null) Arrays.fill(passwordCopy, '\0');
            if (plaintext != null) Arrays.fill(plaintext, (byte) 0);
            if (encrypted != null) Arrays.fill(encrypted, (byte) 0);
        }
    }

    static String doLoad(Map<String, String> req) {
        String masterPassword = req.get("master_password");
        String data = req.get("data");
        if (masterPassword == null || masterPassword.isEmpty()
                || data == null || data.isEmpty()) {
            return err("INVALID_INPUT");
        }
        char[] passwordChars = masterPassword.toCharArray();
        byte[] encrypted = null;
        byte[] plaintext = null;
        try {
            encrypted = Base64.getDecoder().decode(data);
            plaintext = CryptoEngine.decrypt(encrypted, passwordChars);
            Vault loadedVault = Vault.deserialize(plaintext, passwordChars);
            replaceVault(loadedVault);
            return ok();
        } catch (IllegalArgumentException | CryptoEngine.InvalidVaultException e) {
            clearVault();
            return err("INVALID_VAULT");
        } finally {
            Arrays.fill(passwordChars, '\0');
            if (encrypted != null) Arrays.fill(encrypted, (byte) 0);
            if (plaintext != null) Arrays.fill(plaintext, (byte) 0);
        }
    }

    static void replaceVault(Vault nextVault) {
        clearVault();
        activeVault = nextVault;
    }

    static void clearVault() {
        if (activeVault != null) {
            activeVault.clearMasterPassword();
            activeVault = null;
        }
    }

    static String ok()  { return "{\"ok\":true}"; }
    static String err(String code) { return "{\"ok\":false,\"error\":\"" + code + "\"}"; }

    // ---- json ----

    private static final Set<String> KNOWN_FIELDS = Set.of(
            "op", "master_password", "service", "password", "data"
    );
    private static final int MAX_REQUEST_CHARS = 1_000_000;
    private static final int MAX_JSON_DEPTH = 64;

    static Map<String, String> parseJson(String line) {
        if (line == null || line.length() > MAX_REQUEST_CHARS) {
            return null;
        }
        try {
            JsonReader reader = new JsonReader(line);
            Map<String, String> result = reader.parseRequestObject();
            reader.skipWhitespace();
            if (!reader.atEnd()) return null;
            return result;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static final class JsonReader {
        private final String input;
        private int pos;

        JsonReader(String input) {
            if (input == null) throw new IllegalArgumentException();
            this.input = input;
        }

        Map<String, String> parseRequestObject() {
            skipWhitespace();
            expect('{');
            skipWhitespace();
            Map<String, String> result = new HashMap<>();
            Set<String> seenKeys = new HashSet<>();
            if (consumeIf('}')) return result;
            while (true) {
                skipWhitespace();
                String key = parseString();
                if (!seenKeys.add(key)) throw new IllegalArgumentException("Duplicate JSON key.");
                skipWhitespace();
                expect(':');
                skipWhitespace();
                if (KNOWN_FIELDS.contains(key)) {
                    if (atEnd() || input.charAt(pos) != '"')
                        throw new IllegalArgumentException("Protocol field must be a string.");
                    result.put(key, parseString());
                } else {
                    parseValue(1);
                }
                skipWhitespace();
                if (consumeIf('}')) return result;
                expect(',');
            }
        }

        void parseValue(int depth) {
            if (depth > MAX_JSON_DEPTH) {
                throw new IllegalArgumentException("JSON nesting too deep.");
            }
            skipWhitespace();
            if (atEnd()) throw new IllegalArgumentException();
            char c = input.charAt(pos);
            if (c == '"') parseString();
            else if (c == '{') parseObjectValue(depth + 1);
            else if (c == '[') parseArray(depth + 1);
            else if (c == 't') expectWord("true");
            else if (c == 'f') expectWord("false");
            else if (c == 'n') expectWord("null");
            else parseNumber();
        }

        void parseObjectValue(int depth) {
            expect('{');
            skipWhitespace();
            Set<String> seenKeys = new HashSet<>();
            if (consumeIf('}')) return;
            while (true) {
                skipWhitespace();
                String key = parseString();
                if (!seenKeys.add(key)) throw new IllegalArgumentException("Duplicate JSON key.");
                skipWhitespace();
                expect(':');
                parseValue(depth + 1);
                skipWhitespace();
                if (consumeIf('}')) return;
                expect(',');
            }
        }

        void parseArray(int depth) {
            expect('[');
            skipWhitespace();
            if (consumeIf(']')) return;
            while (true) {
                parseValue(depth + 1);
                skipWhitespace();
                if (consumeIf(']')) return;
                expect(',');
            }
        }

        String parseString() {
            expect('"');
            StringBuilder value = new StringBuilder();
            while (!atEnd()) {
                char c = input.charAt(pos++);
                if (c == '"') return value.toString();
                if (c < 0x20) throw new IllegalArgumentException("Control character in string.");
                if (c != '\\') { value.append(c); continue; }
                if (atEnd()) throw new IllegalArgumentException("Incomplete escape.");
                char escaped = input.charAt(pos++);
                switch (escaped) {
                    case '"':  value.append('"');  break;
                    case '\\': value.append('\\'); break;
                    case '/':  value.append('/');  break;
                    case 'b':  value.append('\b'); break;
                    case 'f':  value.append('\f'); break;
                    case 'n':  value.append('\n'); break;
                    case 'r':  value.append('\r'); break;
                    case 't':  value.append('\t'); break;
                    case 'u':  value.append((char) readHex4()); break;
                    default: throw new IllegalArgumentException("Invalid escape.");
                }
            }
            throw new IllegalArgumentException("Unterminated string.");
        }

        int readHex4() {
            if (pos + 4 > input.length()) throw new IllegalArgumentException("Incomplete Unicode escape.");
            int value = 0;
            for (int i = 0; i < 4; i++) {
                int digit = Character.digit(input.charAt(pos++), 16);
                if (digit < 0) throw new IllegalArgumentException("Invalid Unicode escape.");
                value = (value << 4) | digit;
            }
            return value;
        }

        void parseNumber() {
            if (consumeIf('-') && atEnd()) throw new IllegalArgumentException();
            if (consumeIf('0')) {
                // JSON does not permit leading zeroes.
            } else {
                requireDigit('1', '9');
                while (!atEnd() && isDigit(input.charAt(pos))) pos++;
            }
            if (consumeIf('.')) {
                requireDigit('0', '9');
                while (!atEnd() && isDigit(input.charAt(pos))) pos++;
            }
            if (!atEnd() && (input.charAt(pos) == 'e' || input.charAt(pos) == 'E')) {
                pos++;
                if (!atEnd() && (input.charAt(pos) == '+' || input.charAt(pos) == '-')) pos++;
                requireDigit('0', '9');
                while (!atEnd() && isDigit(input.charAt(pos))) pos++;
            }
        }

        void requireDigit(char lower, char upper) {
            if (atEnd()) throw new IllegalArgumentException();
            char c = input.charAt(pos);
            if (c < lower || c > upper) throw new IllegalArgumentException();
            pos++;
        }

        boolean isDigit(char c) { return c >= '0' && c <= '9'; }

        void expectWord(String word) {
            if (!input.startsWith(word, pos)) throw new IllegalArgumentException();
            pos += word.length();
        }

        void skipWhitespace() {
            while (!atEnd()) {
                char c = input.charAt(pos);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') pos++;
                else return;
            }
        }

        boolean consumeIf(char expected) {
            if (!atEnd() && input.charAt(pos) == expected) { pos++; return true; }
            return false;
        }

        void expect(char expected) {
            if (atEnd() || input.charAt(pos) != expected) throw new IllegalArgumentException();
            pos++;
        }

        boolean atEnd() { return pos >= input.length(); }
    }

    static String jsonEscape(String s) {
        StringBuilder sb = new StringBuilder();
        for (int k = 0; k < s.length(); k++) {
            char c = s.charAt(k);
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n");  break;
                case '\r': sb.append("\\r");  break;
                case '\t': sb.append("\\t");  break;
                case '\b': sb.append("\\b");  break;
                case '\f': sb.append("\\f");  break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        return sb.toString();
    }
}
