package burp;

import burp.api.montoya.utilities.ByteUtils;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import java.util.regex.Pattern;


class Attributes {
    private HashMap<String, Object> fingerprint;

    static final Pattern EMAIL = Pattern.compile("@[A-Za-z0-9+_-]{3,}[.][.A-Za-z0-9+_-]{2,}\\w");
    // static final Pattern PHONE = Pattern.compile("^\\s*(?:\\+?(\\d{1,3}))?[-. (]*(\\d{3})[-. )]*(\\d{3})[-. ]*(\\d{4})(?: *x(\\d+))?\\s*$");
    static final Pattern IP = Pattern.compile("[\"']\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}[\"']");

    //private final String[] keys = {"wrtqz"};

    Attributes(Resp resp) {
        fingerprint = new HashMap<>();
        byte[] response = resp.getReq().getResponse();
        fingerprint.put("reflections", Utilities.countMatches(response, "xz340fk".getBytes()));
        fingerprint.put("SSRF", Utilities.countMatches(response, "3b4uebjgjjr6z8rq3jsku8zjigz".getBytes()));
        fingerprint.put("status", resp.getStatus());
        fingerprint.put("email", Utilities.montoyaApi.utilities().byteUtils().countMatches(response, EMAIL));
        fingerprint.put("ip", Utilities.montoyaApi.utilities().byteUtils().countMatches(response, IP));
        fingerprint.put("useragent", Utilities.countMatches(response, "Mozilla/5.0".getBytes()));
        fingerprint.put("header-vars", Utilities.countMatches(response, "HTTP_".getBytes()));
        // fingerprint.put("phone", Utils.montoyaApi.utilities().byteUtils().countMatches(response, PHONE));

        // todo get header names (nick code from bulkscan)

        //IResponseKeywords responseKeywords = Utilities.helpers.analyzeResponseKeywords(Arrays.asList(keys));
        //IResponseVariations responseDetails = Utilities.helpers.analyzeResponseVariations();
    }
    HashMap<String, Object> getFingerprint() {
        return fingerprint;
    }
}

// Simplified version of Backslash Powered Scanner's Attack.java
public class ResponseGroup {

    private HashMap<String, Object> fingerprint;
    private final String[] otherData = {"ip", "useragent", "reflections", "email"};

    public Resp getFirstResp() {
        return firstResp;
    }

    private Resp firstResp;
    public ResponseGroup() {}

    ResponseGroup add(Resp response) {
        if (firstResp == null) {
            firstResp = response;
        }

        // todo use calculateFingerprint
        HashMap<String, Object> inputPrint = new Attributes(response).getFingerprint();
        HashMap<String, Object> generatedPrint = new HashMap<>();
        if (fingerprint == null) {
            fingerprint = inputPrint;
            return this;
        }

        for (String key: inputPrint.keySet()) {
            if (fingerprint.containsKey(key)) {
                if (fingerprint.get(key).equals(inputPrint.get(key))) {
                    generatedPrint.put(key, fingerprint.get(key));
                } else {
                    //Utilities.out("Throwing out "+key+" due to value diff: "+fingerprint.get(key)+":"+inputPrint.get(key));
                }
            }
        }

        fingerprint = generatedPrint;
        return this;
    }

    boolean matches(Resp response) {
        HashMap<String, Object> inputPrint = new Attributes(response).getFingerprint();
        for (String key: fingerprint.keySet()) {
            if (!fingerprint.get(key).equals(inputPrint.get(key))) {
                return false;
            }
        }
        return true;
    }

    String describeDiff(Resp response) {
        HashMap<String, Object> inputPrint = new Attributes(response).getFingerprint();
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

    boolean gainedInfo(Resp response) {
        HashMap<String, Object> inputPrint = new Attributes(response).getFingerprint();

        for (String key: otherData) {
            int k1 = (Integer) fingerprint.getOrDefault(key, -1);
            int k2 = (Integer) inputPrint.getOrDefault(key, -1);
            if (k1 == -1 || k2 == -1) {
                continue;
            }
            if (k1 < k2) {
                return true;
            }
        }
        return false;
    }

}
