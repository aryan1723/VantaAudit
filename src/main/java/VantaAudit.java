import okhttp3.*;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import javax.swing.*;
import java.io.File;

public class VantaAudit {
    private static final String API_KEY = "API_KEY";
    private static final OkHttpClient client = new OkHttpClient();

    public static void main(String[] args) {
        JFileChooser chooser = new JFileChooser();
        if (chooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
            startAudit(chooser.getSelectedFile());
        }
    }

    public static void startAudit(File file) {
        try {
            int finalScore = 0;
            StringBuilder log = new StringBuilder("--- VantaAudit Logs ---\n");

            // Check 1: Masquerading (+30 points)
            if (HashUtils.isFakeExtension(file)) {
                finalScore += 30;
                log.append("[!] High Risk: File is an Executable disguised as something else!\n");
            }

            // Check 2: Entropy (+20 points if > 7.0)
            double entropy = HashUtils.getEntropy(file);
            log.append(String.format("File Entropy: %.2f\n", entropy));
            if (entropy > 7.0) {
                finalScore += 20;
                log.append("[!] Caution: File content is highly compressed/encrypted (Suspected Packer).\n");
            }

            // Check 3: API reputation (+50 points maximum)
            String hash = HashUtils.getHash(file);
            int apiHits = checkAPI(hash);
            if (apiHits > 0) {
                finalScore += Math.min(50, apiHits * 10);
                log.append("[!] API Threat: ").append(apiHits).append(" scanners flagged this file.\n");
            } else if (apiHits == -1) {
                log.append("[i] Note: File fingerprint unknown to global database.\n");
            }

            displayResult(finalScore, log.toString());

        } catch (Exception e) {
            JOptionPane.showMessageDialog(null, "Audit Failed: " + e.getMessage());
        }
    }

    private static int checkAPI(String hash) throws Exception {
        Request request = new Request.Builder()
                .url("https://www.virustotal.com/api/v3/files/" + hash)
                .addHeader("x-apikey", API_KEY).get().build();

        try (Response response = client.newCall(request).execute()) {
            if (response.code() == 404) return -1;
            if (!response.isSuccessful()) return 0;

            JsonObject json = JsonParser.parseString(response.body().string()).getAsJsonObject();
            return json.getAsJsonObject("data").getAsJsonObject("attributes")
                    .getAsJsonObject("last_analysis_stats").get("malicious").getAsInt();
        }
    }

    private static void displayResult(int score, String log) {
        String status = (score >= 70) ? "DANGEROUS" : (score >= 30) ? "SUSPICIOUS" : "SAFE";
        String message = String.format("VANTA SCORE: %d/100\nSTATUS: %s\n\n%s", score, status, log);

        int type = (score >= 70) ? JOptionPane.ERROR_MESSAGE :
                (score >= 30) ? JOptionPane.WARNING_MESSAGE : JOptionPane.INFORMATION_MESSAGE;

        JOptionPane.showMessageDialog(null, message, "VantaAudit Report", type);
    }
}