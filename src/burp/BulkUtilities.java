package burp;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringEscapeUtils;

import java.util.*;

public class BulkUtilities extends Utilities {
    public BulkUtilities(IBurpExtenderCallbacks incallbacks, HashMap<String, Object> settings, String name) {
        super(incallbacks, settings, name);
    }

    static Attack buildTransformationAttack(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint, String leftAnchor, String payload, String rightAnchor) {

        Resp req = Scan.request(baseRequestResponse.getHttpService(),
                insertionPoint.buildRequest(helpers.stringToBytes(insertionPoint.getBaseValue() + leftAnchor + payload + rightAnchor)));

        req.setHighlight(leftAnchor+payload+rightAnchor);
        return new Attack(req, null, payload, "");
    }

    static boolean similarIsh(Attack noBreakGroup, Attack breakGroup, Attack noBreak, Attack doBreak) {

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

    static boolean similar(Attack doNotBreakAttackGroup, Attack individualBreakAttack) {
        //if (!candidate.getPrint().keySet().equals(individualBreakAttack.getPrint().keySet())) {
        //    return false;
        //}

        for (String key: doNotBreakAttackGroup.getPrint().keySet()) {
            if (!individualBreakAttack.getPrint().containsKey(key)){
                return false;
            }
            if (individualBreakAttack.getPrint().containsKey(key) && !individualBreakAttack.getPrint().get(key).equals(doNotBreakAttackGroup.getPrint().get(key))) {
                return false;
            }
        }

        return true;
    }

    static boolean verySimilar(Attack attack1, Attack attack2) {
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

    static byte[] filterResponse(byte[] response) {

        if (response == null) {
            return new byte[]{'n','u','l','l'};
        }
        byte[] filteredResponse;
        IResponseInfo details = helpers.analyzeResponse(response);

        String inferredMimeType = details.getInferredMimeType();
        if(inferredMimeType.isEmpty()) {
            inferredMimeType = details.getStatedMimeType();
        }
        inferredMimeType = inferredMimeType.toLowerCase();

        if(inferredMimeType.contains("text") || inferredMimeType.equals("html") || inferredMimeType.contains("xml") || inferredMimeType.contains("script") || inferredMimeType.contains("css") || inferredMimeType.contains("json")) {
            filteredResponse = helpers.stringToBytes(helpers.bytesToString(response).toLowerCase());
        }
        else {
            String headers = helpers.bytesToString(Arrays.copyOfRange(response, 0, details.getBodyOffset())) + details.getInferredMimeType();
            filteredResponse = helpers.stringToBytes(headers.toLowerCase());
        }

        if(details.getStatedMimeType().toLowerCase().contains("json") && (inferredMimeType.contains("json") || inferredMimeType.contains("javascript"))) {
            String headers = helpers.bytesToString(Arrays.copyOfRange(response, 0, details.getBodyOffset()));
            String body =  helpers.bytesToString(Arrays.copyOfRange(response, details.getBodyOffset(), response.length));
            filteredResponse = helpers.stringToBytes(headers + StringEscapeUtils.unescapeJson(body));
        }

        return filteredResponse;
    }

    static boolean identical(Attack candidate, Attack attack2) {
        if (candidate == null) {
            return false;
        }
        return candidate.getPrint().equals(attack2.getPrint());
    }

    public static ArrayList<PartialParam> getQueryParams(byte[] request) {
        ArrayList<PartialParam> params = new ArrayList<>();

        if (request.length == 0) {
            return params;
        }

        int i = 0;
        while(request[i] != '?') {
            i += 1;
            if (i == request.length) {
                return params;
            }
        }

        i += 1;

        while (request[i] != ' ') {
            StringBuilder name = new StringBuilder();
            while (request[i] != ' ') {
                char c = (char) request[i];
                if (c == '=') {
                    i++;
                    break;
                }
                name.append(c);
                i++;
            }

//            if (request[i] == ' ') {
//                break;
//            }

            int valueStart = i;
            int valueEnd;

            while (true) {
                char c = (char) request[i];
                if (c == '&') {
                    valueEnd = i;
                    i++;
                    break;
                }
                if (c == ' ') {
                    valueEnd = i;
                    break;
                }

                i++;
            }

            //BulkUtilities.out("Param: "+name.toString()+"="+value.toString() + " | " + (char) request[valueStart] + " to " + (char) request[valueEnd]);
            params.add(new PartialParam(name.toString(), valueStart, valueEnd, IParameter.PARAM_URL));
            //BulkUtilities.out(BulkUtilities.helpers.bytesToString(new RawInsertionPoint(request, valueStart, valueEnd).buildRequest("injected".getBytes())));
        }

        return params;
    }

    public static PartialParam paramify(byte[] request, String name, String target, String fakeBaseValue) {
//        // todo pass in value maybe
//        if (target.length() != basevalue.length()) {
//            throw new RuntimeException("target length must equal basevalue length");
//        }
        int start = BulkUtilities.helpers.indexOf(request, target.getBytes(), true, 0, request.length);
        if (start == -1) {
            throw new RuntimeException("Failed to find target");
        }
        int end = start + target.length();
        return new PartialParam(name, start, end);
    }

    static IScanIssue reportReflectionIssue(Attack[] attacks, IHttpRequestResponse baseRequestResponse) {
        return reportReflectionIssue(attacks, baseRequestResponse, "", "");
    }

    static IScanIssue reportReflectionIssue(Attack[] attacks, IHttpRequestResponse baseRequestResponse, String title) {
        return reportReflectionIssue(attacks, baseRequestResponse, title, "");
    }

    static IScanIssue reportReflectionIssue(Attack[] attacks, IHttpRequestResponse baseRequestResponse, String title, String detail) {
        IHttpRequestResponse[] requests = new IHttpRequestResponse[attacks.length];
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

                    if(brokeResult.equals(workedResult)) {
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

        return new Fuzzable(requests, baseRequestResponse, title, detail, reliable, reportedSeverity); //attacks[attacks.length-2].getProbe().getName()
    }

    static List<IParameter> getHeaderInsertionPoints(byte[] request, String[] to_poison) {
        List<IParameter> params = new ArrayList<>();
        int end = getBodyStart(request);
        int i = 0;
        while(request[i++] != '\n' && i < end) {}
        while(i<end) {
            int line_start = i;
            while(i < end && request[i++] != ' ') {}
            byte[] header_name = Arrays.copyOfRange(request, line_start, i-2);
            int headerValueStart = i;
            while(i < end && request[i++] != '\n') {}
            if (i == end) { break; }

            String header_str = helpers.bytesToString(header_name);
            for (String header: to_poison) {
                if (header.equals(header_str)) {
                    params.add(new PartialParam(header, headerValueStart, i-2));
                }
            }
        }
        return params;
    }


    static List<IParameter> getExtraInsertionPoints(byte[] request) { //
        List<IParameter> params = new ArrayList<>();
        int end = getBodyStart(request);
        int i = 0;
        while(i < end && request[i++] != ' ') {} // walk to the url start
        while(i < end) {
            byte c = request[i];
            if (c == ' ' ||
                    c == '?' ||
                    c == '#') {
                break;
            }
            i++;
        }

        params.add(new PartialParam("path", i, i));
        while(request[i++] != '\n' && i < end) {}

        String[] to_poison = {"User-Agent", "Referer", "X-Forwarded-For", "Host"};
        params.addAll(getHeaderInsertionPoints(request, to_poison));

        return params;
    }

}


class Fuzzable extends CustomScanIssue {

    private final static String REMEDIATION = "This issue does not necessarily indicate a vulnerability; it is merely highlighting behaviour worthy of manual investigation. Try to determine the root cause of the observed behaviour." +
            "Refer to <a href='http://blog.portswigger.net/2016/11/backslash-powered-scanning-hunting.html'>Backslash Powered Scanning</a> for further details and guidance interpreting results. ";

    Fuzzable(IHttpRequestResponse[] requests, IHttpRequestResponse baseRequestResponse, String title, String detail, boolean reliable, String severity) {
        super(requests[0].getHttpService(), BulkUtilities.analyzeRequest(baseRequestResponse).getUrl(), ArrayUtils.add(requests, 0, baseRequestResponse), title, detail, severity, calculateConfidence(reliable), REMEDIATION);
    }

    private static String calculateConfidence(boolean reliable) {
        String confidence = "Tentative";
        if (reliable) {
            confidence = "Firm";
        }
        return confidence;
    }

}