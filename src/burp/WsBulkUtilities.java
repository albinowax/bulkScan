package burp;

import java.util.*;

import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.commons.lang3.ArrayUtils;

import org.json.JSONObject;
import org.json.JSONException;
import org.json.JSONArray;

import java.util.regex.Pattern;
import java.util.regex.Matcher;

class WsBulkUtilities {
    public static boolean verySimilar(WsAttack attack1, WsAttack attack2) {
        if (!attack1.getPrint().keySet().equals(attack2.getPrint().keySet())) {
            return false;
        }

        for (String key: attack1.getPrint().keySet()) {
            if(key.equals("input_reflections") && (attack1.getPrint().get(key).equals(Attack.INCALCULABLE) || attack2.getPrint().get(key).equals(Attack.INCALCULABLE))) {
                continue;
            }

            if (attack2.getPrint().containsKey(key) && !attack2.getPrint().get(key).equals(attack1.getPrint().get(key))) {
                return false;
            }
        }

        return true;
    }

    public static boolean identical(WsAttack candidate, WsAttack attack2) {
        if (candidate == null) {
            return false;
        }

        return candidate.getPrint().equals(attack2.getPrint());
    }

    public static boolean similar(WsAttack doNotBreakAttackGroup, WsAttack individualBreakAttack) {
        for (String key: doNotBreakAttackGroup.getPrint().keySet()) {
            if (!individualBreakAttack.getPrint().containsKey(key)) {
                return false;
            }
            if (individualBreakAttack.getPrint().containsKey(key) && !individualBreakAttack.getPrint().get(key).equals(doNotBreakAttackGroup.getPrint().get(key))) {
                return false;
            }
        }

        return true;
    }

    public static boolean similarIsh(WsAttack noBreakGroup, WsAttack breakGroup, WsAttack noBreak, WsAttack doBreak) {
        for (String key: noBreakGroup.getPrint().keySet()) {
            Object noBreakVal = noBreakGroup.getPrint().get(key);

            if(key.equals("input_reflections") && noBreakVal.equals(Attack.INCALCULABLE)) {
                continue;
            }

            // if this attribute is inconsistent, make sure it's different this time
            if (!breakGroup.getPrint().containsKey(key)) {
                if (!noBreakVal.equals(doBreak.getPrint().get(key))) {
                    return false;
                }
            }
            else if (!noBreakVal.equals(breakGroup.getPrint().get(key))) {
                // if it's consistent and different, these responses definitely don't match
                return false;
            }
        }

        for (String key: breakGroup.getPrint().keySet()) {
            if (!noBreakGroup.getPrint().containsKey(key)) {
                // if this attribute is inconsistent, make sure it's different this time
                if (!breakGroup.getPrint().get(key).equals(noBreak.getPrint().get(key))){
                    return false;
                }
            }
        }

        return true;
    }

    public static IScanIssue reportReflectionIssue(WsAttack[] attacks, IHttpRequestResponse baseRequestResponse, String title, String detail) {
        WebSocketMessageImpl[] requests = new WebSocketMessageImpl[attacks.length];
        Probe bestProbe = null;
        boolean reliable = false;
        detail = detail + "<br/><br/><b>Successful probes</b><br/>";
        String reportedSeverity = "High";
        int evidenceCount = 0;

        for (int i=0; i<attacks.length; i++) {
            requests[i] = attacks[i].getFastestRequest(); // was getFirstRequest
            if (i % 2 == 0) {
                detail += " &#160;  &#160; <table><tr><td><b>"+StringEscapeUtils.escapeHtml4(attacks[i].getProbe().getName())+" &#160;  &#160; </b></td><td><b>"+ StringEscapeUtils.escapeHtml4(attacks[i].payload)+ " &#160; </b></td><td><b>";
            }
            else {
                detail += StringEscapeUtils.escapeHtml4(attacks[i].payload)+"</b></td></tr>\n";
                HashMap<String, Object> workedPrint = attacks[i].getLastPrint(); // was getFirstPrint
                HashMap<String, Object> consistentWorkedPrint = attacks[i].getPrint();
                HashMap<String, Object> breakPrint = attacks[i-1].getLastPrint(); // was getFirstPrint
                HashMap<String, Object> consistentBreakPrint = attacks[i-1].getPrint();

                Set<String> allKeys = new HashSet<>(consistentWorkedPrint.keySet());
                allKeys.addAll(consistentBreakPrint.keySet());
                String boringDetail = "";

                for (String mark: allKeys) {
                    Object brokeResult = breakPrint.get(mark);
                    Object workedResult = workedPrint.get(mark);

                    // handle null or invalid values
                    if (brokeResult == null) brokeResult = 0;
                    if (workedResult == null) workedResult = 0;

                    if (brokeResult.equals(workedResult)) {
                        continue;
                    }

                    evidenceCount++;

                    try {
                        if (Math.abs(Integer.parseInt(brokeResult.toString())) > 9999) {
                            brokeResult = "X";
                        }
                        if (Math.abs(Integer.parseInt(workedResult.toString())) > 9999) {
                            workedResult = "Y";
                        }
                    }
                    catch (NumberFormatException e) {
                        brokeResult = StringEscapeUtils.escapeHtml4(brokeResult.toString());
                        workedResult = StringEscapeUtils.escapeHtml4(workedResult.toString());
                    }

                    if (consistentBreakPrint.containsKey(mark) && consistentWorkedPrint.containsKey(mark)) {
                        detail += "<tr><td>" + StringEscapeUtils.escapeHtml4(mark) + "</td><td>" + "" + brokeResult + " </td><td>" + workedResult + "</td></tr>\n";
                        reliable = true;
                    }
                    else if (consistentBreakPrint.containsKey(mark)) {
                        boringDetail += "<tr><td><i>" + StringEscapeUtils.escapeHtml4(mark)+"</i></td><td><i>" + brokeResult + "</i></td><td><i> *" + workedResult + "*</i></td></tr>\n";
                    }
                    else {
                        boringDetail += "<tr><td><i>" + StringEscapeUtils.escapeHtml4(mark)+"</i></td><td><i>*" + brokeResult + "*</i></td><td><i>" + workedResult + "</i></td></tr>\n";
                    }

                }
                detail += boringDetail;
                detail += "</table>\n";

                String tip = attacks[i].getProbe().getTip();
                if (!"".equals(tip)) {
                    detail += "&nbsp;<i>"+tip+"</i>";
                }
            }

            if (bestProbe == null || attacks[i].getProbe().getSeverity() >= bestProbe.getSeverity()) {
                bestProbe = attacks[i].getProbe();

                int severity = bestProbe.getSeverity();
                if (severity < 3) {
                    reportedSeverity = "Low";
                }
                else if (severity < 7) {
                    reportedSeverity = "Medium";
                }

            }
        }

        if (evidenceCount == 1) {
            reportedSeverity = "Information";
        }

        if ("Interesting input handling".equals(title)) {
            title = bestProbe.getName();
        }

        WsFuzzable issue = new WsFuzzable(requests, baseRequestResponse, title, detail, reliable, reportedSeverity);
        Utilities.callbacks.addScanIssue(issue);
        return issue;
    }
    
    public static List<String> getInsertionPoints(String message) {
        List<String> insertionPoints = new ArrayList<>();

        Pattern pattern = Pattern.compile("FU(.*)ZZ");
        Matcher matcher = pattern.matcher(message);
        if (matcher.find()) {
            insertionPoints.add(message);
        } else {
            try {
                if (message.matches("^\\d+\\[\"[^\"]+\",\\s*\\{.*}]$")) {
                    int bracketStart = message.indexOf('[');
                    int bracketEnd = message.lastIndexOf(']');
                    if (bracketStart != -1 && bracketEnd != -1) {
                        String content = message.substring(bracketStart + 1, bracketEnd);
                        String[] parts = content.split(",", 2);
                
                        if (parts.length == 2) {
                            // process event name
                            String eventName = parts[0].trim();
                            if (eventName.startsWith("\"") && eventName.endsWith("\"")) {
                                eventName = eventName.substring(1, eventName.length() - 1);
                            }
                    
                            // process json data
                            String jsonData = parts[1].trim();
                            JSONObject jsonObject = new JSONObject(jsonData);
                    
                            // Generate variations
                            List<String> jsonVariations = new ArrayList<>();
                            processJsonObject(jsonObject, jsonVariations);

                            // For each JSON variation, create the corresponding Socket.IO message
                            for (String jsonVar : jsonVariations) {
                                String modified = message.substring(0, bracketStart + 1) + 
                                        "\"" + eventName + "\"," + 
                                        jsonVar + 
                                        message.substring(bracketEnd);
                                insertionPoints.add(modified);
                            }
                    
                            // Also add variation where only the event name is modified
                            String eventModified = message.substring(0, bracketStart + 1) + 
                                          "\"FU" + eventName + "ZZ\"," + 
                                          jsonData + 
                                          message.substring(bracketEnd);
                            insertionPoints.add(eventModified);
                        }
                    }
                } else {
                    JSONObject jsonObject = new JSONObject(message);
                    processJsonObject(jsonObject, insertionPoints);
                }
            } catch (JSONException e) {
                insertionPoints.add("FU" + message + "ZZ");
            }
        }

        return insertionPoints;
    }

    private static void processJsonObject(JSONObject jsonObject, List<String> insertionPoints) {
        Iterator<String> keys = jsonObject.keys();

        while (keys.hasNext()) {
            String key = keys.next();
            Object value = jsonObject.get(key);
    
            // Create key modification
            JSONObject keyInsertion = new JSONObject(jsonObject.toString());
            keyInsertion.remove(key);
            keyInsertion.put("FU" + key + "ZZ", value);
            insertionPoints.add(keyInsertion.toString());
    
            if (value instanceof JSONObject) {
                JSONObject nestedValue = (JSONObject) value;
            
                // Process nested object without modifying parent yet
                List<String> nestedPoints = new ArrayList<>();
                processJsonObject(nestedValue, nestedPoints);
            
                // For each nested modification, create a parent modification
                for (String nestedModified : nestedPoints) {
                    //JSONObject modifiedParent = new JSONObject(jsonObject.toString());
                    //modifiedParent.put(key, new JSONObject(nestedModified));
                    String modifiedParent = jsonObject.toString().replace(
                        "\"" + key + "\":" + value.toString(),
                        "\"" + key + "\":" + nestedModified 
                    );
                
                    insertionPoints.add(modifiedParent.toString());
                }
            } 
            else {
                // Create value modification
                JSONObject valueInsertion = new JSONObject(jsonObject.toString());
            
                if (value instanceof String) {
                    valueInsertion.put(key, "FU" + value + "ZZ");
                    insertionPoints.add(valueInsertion.toString());
                } else {
                    // For non-strings, we need to handle the value carefully
                    String jsonString = valueInsertion.toString();
                    String valueStr = value.toString();
                    String modifiedJson = jsonString.replace(
                        "\"" + key + "\":" + valueStr,
                        "\"" + key + "\":FU" + valueStr + "ZZ"
                    );

                    insertionPoints.add(modifiedJson);
                }
            }
        }
    }
}

class WsFuzzable extends CustomScanIssue {

    private final static String REMEDIATION = "This issue does not necessarily indicate a vulnerability; it is merely highlighting behaviour worthy of manual investigation. Try to determine the root cause of the observed behaviour." +
            "Refer to <a href='http://blog.portswigger.net/2016/11/backslash-powered-scanning-hunting.html'>Backslash Powered Scanning</a> for further details and guidance interpreting results. ";

    WsFuzzable(WebSocketMessageImpl[] requests, IHttpRequestResponse baseRequestResponse, String title, String detail, boolean reliable, String severity) {
        super(baseRequestResponse.getHttpService(), BulkUtilities.analyzeRequest(baseRequestResponse).getUrl(), new IHttpRequestResponse[]{baseRequestResponse}, title, detail, severity, calculateConfidence(reliable), REMEDIATION);
    }

    private static String calculateConfidence(boolean reliable) {
        String confidence = "Tentative";
        if (reliable) {
            confidence = "Firm";
        }
        return confidence;
    }

}
