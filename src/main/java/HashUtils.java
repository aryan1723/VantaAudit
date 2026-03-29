import java.io.File;
import java.io.FileInputStream;
import java.security.MessageDigest;
import java.nio.file.Files;

public class HashUtils {

    // 1. Calculate File Entropy (Detects Hidden/Encrypted Code)
    public static double getEntropy(File file) throws Exception {
        byte[] fileData = Files.readAllBytes(file.toPath());
        int[] frequencies = new int[256];
        for (byte b : fileData) frequencies[b & 0xFF]++;

        double entropy = 0;
        double total = fileData.length;
        for (int freq : frequencies) {
            if (freq > 0) {
                double p = freq / total;
                entropy -= p * (Math.log(p) / Math.log(2));
            }
        }
        return entropy;
    }

    // 2. Detect Masquerading (Magic Bytes Check)
    public static boolean isFakeExtension(File file) throws Exception {
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] header = new byte[4];
            fis.read(header);
            StringBuilder hex = new StringBuilder();
            for (byte b : header) hex.append(String.format("%02x", b));

            String sig = hex.toString().toLowerCase();
            String name = file.getName().toLowerCase();

            // Flag if it's an EXE (4d5a) but named as something else
            return sig.startsWith("4d5a") && !name.endsWith(".exe") && !name.endsWith(".dll");
        }
    }

    // 3. Generate SHA-256 for VirusTotal
    public static String getHash(File file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] encodedHash = digest.digest(Files.readAllBytes(file.toPath()));
        StringBuilder hexString = new StringBuilder();
        for (byte b : encodedHash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }
}