package burp;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

public class CustomResponseGroup {

    private Function<HttpRequestResponse, HashMap<String, Object>> calculateFingerprint;
    private HashMap<String, Object> fingerprint;
    public Resp getFirstResp() {
        return firstResp;
    }

    private Resp firstResp;

    public CustomResponseGroup(Function<HttpRequestResponse, HashMap<String, Object>> calculateFingerprint, HttpRequestResponse resp) {
        this.calculateFingerprint = calculateFingerprint;
        add(resp);
    }

    public CustomResponseGroup(Function<HttpRequestResponse, HashMap<String, Object>> calculateFingerprint) {
        this.calculateFingerprint = calculateFingerprint;
    }

    CustomResponseGroup add(HttpRequestResponse response) {
        if (firstResp == null) {
            firstResp = new Resp(response);
        }

        // todo use calculateFingerprint
        HashMap<String, Object> inputPrint = calculateFingerprint.apply(response);
        HashMap<String, Object> generatedPrint = new HashMap<>();
        if (fingerprint == null) {
            fingerprint = inputPrint;
            return this;
        }

        for (String key: inputPrint.keySet()) {
            if (fingerprint.containsKey(key)) {
                if (Objects.equals(fingerprint.get(key), inputPrint.get(key))) {
                    generatedPrint.put(key, fingerprint.get(key));
                } else {
                    //Utilities.out("Throwing out "+key+" due to name diff: "+fingerprint.get(key)+":"+inputPrint.get(key));
                }
            }
        }

        fingerprint = generatedPrint;
        return this;
    }

    boolean matches(HttpRequestResponse response) {
        HashMap<String, Object> inputPrint = calculateFingerprint.apply(response);

        for (String key: fingerprint.keySet()) {
            if (!Objects.equals(fingerprint.get(key), inputPrint.get(key))) {
                return false;
            }
        }
        return true;
    }

    boolean badFingerprint() {
        return fingerprint.isEmpty();
    }

    ArrayList<String> diffKeys(HttpRequestResponse response) {
        ArrayList<String> diffKeys = new ArrayList<>();
        HashMap<String, Object> inputPrint = calculateFingerprint.apply(response);
        for (String key: fingerprint.keySet()) {
            if (!fingerprint.get(key).equals(inputPrint.get(key))) {
                diffKeys.add(key);
            }
        }
        return diffKeys;
    }

    String describeDiff(HttpRequestResponse response) {
        HashMap<String, Object> inputPrint = calculateFingerprint.apply(response);
        StringBuilder diff = new StringBuilder();
        diff.append("attribute expected:attack<br>\n");
        for (String key: fingerprint.keySet()) {
            if (!fingerprint.get(key).equals(inputPrint.get(key))) {
                diff.append(key);
                diff.append(" ");
                diff.append(fingerprint.get(key));
                diff.append(":");
                diff.append(inputPrint.get(key));
                diff.append("<br>\n");
            }
        }
        return diff.toString();
    }

    public String toString() {
        StringBuilder out = new StringBuilder();
        for (Map.Entry<String, Object> e: fingerprint.entrySet()) {
            out.append(e.getKey());
            out.append(":");
            out.append(e.getValue());
        }
        return out.toString();
    }

}

