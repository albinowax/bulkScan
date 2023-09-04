package burp;

import java.util.*;

/**
 * Created by james on 24/11/2016.
 */
class Attack {
    final static int UNINITIALISED = -1;
    final static int DYNAMIC = -2;
    final static int INCALCULABLE = -3;

    private Resp firstRequest;

    private Resp fastestRequest;

    HashMap<String, Object> getLastPrint() {
        return lastPrint;
    }

    private HashMap<String, Object> lastPrint;

    Resp getFastestRequest() {
        return fastestRequest;
    }

    private Resp lastRequest;

    private String[] keys = new String[]{BulkUtilities.globalSettings.getString("canary"), "\",\"", "true", "false", "\"\"", "[]", "</html>", "error", "exception", "invalid", "warning", "stack", "sql syntax", "divisor", "divide", "ora-", "division", "infinity", "<script", "<div"};

    private ArrayList<QuantitativeMeasurements> quantBoxes;
    private HashSet<String> quantkeys;
    String payload;
    private Probe probe;
    private String anchor;
    private HashMap<String, Object> fingerprint;

    private IResponseKeywords responseKeywords = BulkUtilities.helpers.analyzeResponseKeywords(Arrays.asList(keys));
    private IResponseVariations responseDetails = new FastResponseVariations();//BulkUtilities.helpers.analyzeResponseVariations();

    // todo add response end?
    private int responseReflections = UNINITIALISED;

    public Attack(Resp req, Probe probe, String payload, String anchor) {
        this.firstRequest = req;
        this.lastRequest = req;
        this.fastestRequest = req;
        this.probe = probe;
        this.payload = payload;
        this.anchor = anchor;
        intialiseQuantitativeMeasurements();
        add(req, anchor);
        this.lastPrint = fingerprint;

    }

    public Attack(Resp req) {
        this.firstRequest = req;
        this.lastRequest = req;
        this.fastestRequest = req;
        intialiseQuantitativeMeasurements();
        add(req, "");
        this.lastPrint = fingerprint;

    }

    public Attack() {
        intialiseQuantitativeMeasurements();
    }

    private void intialiseQuantitativeMeasurements(){
        List<String> keys = Arrays.asList(BulkUtilities.globalSettings.getString("quantitative diff keys").split(","));
        quantkeys = new HashSet<>(keys);
        quantkeys.remove("");
        quantBoxes = new ArrayList<>();
        for (String key: quantkeys) {
            quantBoxes.add(new QuantitativeMeasurements(key));
        }
    }

    public HashMap<String, Object> getPrint() {
        return fingerprint;
    }

    public Resp getFirstRequest() {
        return firstRequest;
    }

    public int size() {
        return quantBoxes.get(0).measurements.size();
    } // this is not good

    public boolean allKeysAreQuantitative(HashSet<String> keys) {
        return quantkeys.containsAll(keys);
    }

    private void regeneratePrint() {
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

        for (QuantitativeMeasurements quant: quantBoxes) {
            generatedPrint.put(quant.key, quant);
        }

        fingerprint = generatedPrint;
    }

    private void updateFastestRequest(Resp resp) {
        if (resp.getResponseTime() < fastestRequest.getResponseTime()) {
            fastestRequest = resp;
        }
    }

    Probe getProbe() {
        return probe;
    }

    private Attack add(Resp resp, String anchor) {
        assert (firstRequest != null);


        byte[] response = BulkUtilities.filterResponse(resp.getReq().getResponse());
        responseKeywords.updateWith(response);
        responseDetails.updateWith(response);

        for (QuantitativeMeasurements box: quantBoxes) {
            box.updateWith(resp);
        }

        if(anchor == null || anchor.equals("")) {
            responseReflections = INCALCULABLE;
        }
        else {
            int reflections = BulkUtilities.countMatches(response, anchor.getBytes());
            if (responseReflections == UNINITIALISED) {
                responseReflections = reflections;
            } else if (responseReflections != reflections && responseReflections != INCALCULABLE) {
                responseReflections = DYNAMIC;
            }
        }

        regeneratePrint();
        updateFastestRequest(resp);

        return this;
    }

    Attack addAttack(Attack attack) {
        if(firstRequest == null) {
            firstRequest = attack.firstRequest;
            fastestRequest = attack.fastestRequest;
            anchor = attack.anchor;
            probe = attack.getProbe();
            payload = attack.payload;
            add(attack.getFirstRequest(), anchor);
            intialiseQuantitativeMeasurements(); // shouldn't this be before add()?
        }

        //add(attack.firstRequest.getResponse(), anchor);
        HashMap<String, Object> generatedPrint = new HashMap<>();
        HashMap<String, Object> inputPrint = attack.getPrint();
        for (String key: inputPrint.keySet()) {
            if (fingerprint.containsKey(key)) {
                if (quantkeys.contains(key)) {
                    QuantitativeMeasurements quantBox = (QuantitativeMeasurements) inputPrint.get(key);
                    quantBox.merge((QuantitativeMeasurements) fingerprint.get(key));
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

    static HashSet<String> getNonMatchingPrints(Attack attack1, Attack attack2) {
        Set<String> allKeys = new HashSet<>(attack1.fingerprint.keySet());
        allKeys.addAll(attack2.fingerprint.keySet());

        HashSet<String> nonMatching = new HashSet<>();
        for (String key: allKeys) {
            if( !attack1.lastPrint.get(key).equals(attack2.lastPrint.get(key))) {
                nonMatching.add(key);
            }
        }
        return nonMatching;
    }

}
