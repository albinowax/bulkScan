package burp;

import java.util.*;

import burp.api.montoya.core.ByteArray;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

class WsAttack {
    final static int UNINITIALISED = -1;
    final static int DYNAMIC = -2;
    final static int INCALCULABLE = -3;
    
    private WebSocketMessageImpl firstRequest;

    private WebSocketMessageImpl fastestRequest;
    
    HashMap<String, Object> getLastPrint() {
        return lastPrint;
    }

    private HashMap<String, Object> lastPrint;

    WebSocketMessageImpl getFastestRequest() {
        return fastestRequest;
    }

    private WebSocketMessageImpl lastRequest;

    private String[] keys = new String[]{BulkUtilities.globalSettings.getString("canary"), "\",\"", "true", "false", "\"\"", "[]", "</html>", "error", "exception", "invalid", "warning", "stack", "sql syntax", "divisor", "divide", "ora-", "division", "infinity", "<script", "<div"};

    private ArrayList<WsQuantitativeMeasurements> quantBoxes;
    private HashSet<String> quantkeys;
    String payload;
    private Probe probe;
    private String anchor;
    private HashMap<String, Object> fingerprint;

    private IResponseKeywords responseKeywords = BulkUtilities.helpers.analyzeResponseKeywords(Arrays.asList(keys));
    private WsFastResponseVariations responseDetails = new WsFastResponseVariations();

    private int responseReflections = UNINITIALISED;

    public WsAttack(WebSocketMessageImpl req, Probe probe, String payload, String anchor) {
        this.firstRequest = req;
        this.lastRequest = req;
        this.fastestRequest = req;
        this.probe = probe;
        this.payload = payload;
        this.anchor = anchor;
        intialiseWsQuantitativeMeasurements();
        add(req, anchor);
        this.lastPrint = fingerprint;
    }

    public WsAttack(WebSocketMessageImpl req) {
        this.firstRequest = req;
        this.lastRequest = req;
        this.fastestRequest = req;
        intialiseWsQuantitativeMeasurements();
        add(req, "");
        this.lastPrint = fingerprint;
    }

    public WsAttack() {
        intialiseWsQuantitativeMeasurements();
    }

     private void intialiseWsQuantitativeMeasurements() {
         List<String> keys = Arrays.asList(BulkUtilities.globalSettings.getString("quantitative diff keys").split(","));
         quantkeys = new HashSet<>(keys);
         quantkeys.remove("");
         quantBoxes = new ArrayList<>();
         for (String key: quantkeys) {
             quantBoxes.add(new WsQuantitativeMeasurements(key));
         }
     }

    public HashMap<String, Object> getPrint() {
        return fingerprint;
    }

    public WebSocketMessageImpl getFirstRequest() {
        return firstRequest;
    }
    
     public int size() {
         return quantBoxes.get(0).measurements.size();
     }
 
     public boolean allKeysAreQuantitative(HashSet<String> keys) {
         return quantkeys.containsAll(keys);
     }

    public void regeneratePrint() {
        HashMap<String, Object> generatedPrint = new HashMap<>();
        List<String> keys = responseKeywords.getInvariantKeywords();
        for (String key : keys) {
            generatedPrint.put(key, responseKeywords.getKeywordCount(key, 0));
        }

        keys = responseDetails.getInvariantAttributes();
        for (String key : keys) {
            generatedPrint.put(key, responseDetails.getAttributeValue(key, 0));
        }

        if (responseReflections != DYNAMIC) {
            generatedPrint.put("input_reflections", responseReflections);
        }

         for (WsQuantitativeMeasurements quant : quantBoxes) {
             generatedPrint.put(quant.key, quant);
         }

        fingerprint = generatedPrint;
    }
    
    private void updateFastestRequest(WebSocketMessageImpl webSocketMessage) {
        if (webSocketMessage.responseTime() < fastestRequest.responseTime()) {
            fastestRequest = webSocketMessage;
        }
    }

    Probe getProbe() {
        return probe;
    }

    private WsAttack add(WebSocketMessageImpl webSocketMessage, String anchor) {
        assert (firstRequest != null);

        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            for (ByteArray responseByteArray : webSocketMessage.responses()) {
                baos.write(responseByteArray.getBytes());
            }

            responseKeywords.updateWith(baos.toByteArray());
        } catch (IOException e) {
            throw new RuntimeException("Failed to concatenate responses", e);
        }
        responseDetails.updateWith(webSocketMessage);

         for (WsQuantitativeMeasurements box: quantBoxes) {
             box.updateWith(webSocketMessage);
         }

        if (anchor == null || anchor.equals("")) {
            responseReflections = INCALCULABLE;
        } else {
            int reflections = 0;
                for (ByteArray responseByteArray : webSocketMessage.responses()) {
                byte[] response = responseByteArray.getBytes();
                reflections += BulkUtilities.countMatches(response, anchor.getBytes());
            }
            if (responseReflections == UNINITIALISED) {
                responseReflections = reflections;
            } else if (responseReflections != reflections && responseReflections != INCALCULABLE) {
                responseReflections = DYNAMIC;
            }
        }

        regeneratePrint();
        updateFastestRequest(webSocketMessage);

        return this;
    }

    WsAttack addAttack(WsAttack attack) {
        if (firstRequest == null) {
            firstRequest = attack.firstRequest;
            fastestRequest = attack.fastestRequest;
            anchor = attack.anchor;
            probe = attack.getProbe();
            payload = attack.payload;
            add(attack.getFirstRequest(), anchor);
            intialiseWsQuantitativeMeasurements();
        }

        HashMap<String, Object> generatedPrint = new HashMap<>();
        HashMap<String, Object> inputPrint = attack.getPrint();
        for (String key: inputPrint.keySet()) {
            if (fingerprint.containsKey(key)) {
                if (quantkeys.contains(key)) {
                    WsQuantitativeMeasurements quantBox = (WsQuantitativeMeasurements) inputPrint.get(key);
                    quantBox.merge((WsQuantitativeMeasurements) fingerprint.get(key));
                    generatedPrint.put(key, quantBox);
                } else if (fingerprint.get(key).equals(inputPrint.get(key))) {
                    generatedPrint.put(key, fingerprint.get(key));
                }
            }
        }

        fingerprint = generatedPrint;
        lastRequest = attack.lastRequest;
        updateFastestRequest(attack.fastestRequest);
        this.lastPrint = attack.getPrint();

        return this;
    }

    static HashSet<String> getNonMatchingPrints(WsAttack attack1, WsAttack attack2) {
        Set<String> allKeys = new HashSet<>(attack1.fingerprint.keySet());
        allKeys.addAll(attack2.fingerprint.keySet());

        HashSet<String> nonMatching = new HashSet<>();
        for (String key: allKeys) {
            if (!attack1.lastPrint.get(key).equals(attack2.lastPrint.get(key))) {
                nonMatching.add(key);
            }
        }

        return nonMatching;
    }
}
