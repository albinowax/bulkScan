package burp;

import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import org.apache.commons.lang3.NotImplementedException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

abstract class Scan implements IScannerCheck {
    static ZgrabLoader loader = null;

    String name = "";
    SettingsBox scanSettings;

    Scan(String name) {
        this.name = name;
        BulkScan.scans.add(this);
        scanSettings = new SettingsBox();

        // any-scan settings
        scanSettings.register("per-thread throttle", 0, "Pause for X ms before sending each request");
        scanSettings.register("thread pool size", 8, "The maximum number of threads created for attacks. This roughly equates to the number of concurrent HTTP requests. Increase this number to make large scale attacks go faster, or decrease it to reduce your system load.");
        scanSettings.register("use key", true, "Avoid scanning similar endpoints by generating a key from each request's hostname and protocol, and skipping subsequent requests with matching keys.");
        scanSettings.register("key method", true, "Include the request method in the key");
        scanSettings.register("key path", false, "Include the request path in the key");
        scanSettings.register("key status", true, "Include the response status code in the key");
        scanSettings.register("key content-type", true, "Include the response content-type in the key");
        scanSettings.register("key server", true, "Include the response Server header in the key");
        scanSettings.register("key input name", true, "Include the name of the parameter being scanned in the key");
        scanSettings.register("key header names", false, "Include all response header names (but not values) in the key");
        scanSettings.register("filter", "", "Only scan requests containing the configured string");
        scanSettings.register("mimetype-filter", "", "Only scan responses with the configured string in their mimetype");
        scanSettings.register("resp-filter", "", "Only scan requests with responses containing the configured string.");
        scanSettings.register("filter HTTP", false, "Only scan HTTPS requests");
        scanSettings.register("skip vulnerable hosts", false, "Don't scan hosts already flagged as vulnerable during this scan. Reload the extension to clear flags.");
        scanSettings.register("skip flagged hosts", false, "Don't report issues on hosts already flagged as vulnerable");
        scanSettings.register("flag new domains", false, "Adjust the title of issues reported on hosts that don't have any other issues listed in the sitemap");
        scanSettings.register("report to organizer", false, "Send detected vulnerabilities to the Organizer");

        // specific-scan settings TODO remove
        scanSettings.register("confirmations", 5, "The number of repeats used to confirm behaviour is consistent. Increase this to reduce false positives caused by random noise");
        scanSettings.register("require consistent evidence", true, "Ignore less reliable issues");

        scanSettings.register("quantile factor", 2, "1-10. Higher means fewer false positives. Lower means fewer false negatives.");
        scanSettings.register("quantitative diff keys", "", "Support ranges of quantitative values like word_count. Experimental.");
        scanSettings.register("quantitative confirmations", 50, "The number of repeats used to confirm quantitative behaviour is consistent.");
        scanSettings.register("include query-param in cachebusters", true);
        scanSettings.register("include origin in cachebusters", true);
        scanSettings.register("include path in cachebusters", false);
        scanSettings.register("include via in cachebusters", true);
        scanSettings.register("misc header cachebusters", false);
        scanSettings.register("custom header cachebuster", "");

        //BulkUtilities.callbacks.registerScannerCheck(this);
    }

    List<String> getSettings() {
//        Set<String> settings = new HashSet<>();
//        settings.addAll(scanSettings.getSettings());
//        settings.addAll(BulkScanLauncher.genericSettings.getSettings());
//        return new ArrayList<>(settings);
        return scanSettings.getSettings();
    }

    boolean supportsRequestScan() {
        return true;
    }

    List<IScanIssue> doScan(byte[] baseReq, IHttpService service) {
        throw new RuntimeException("doScan(byte[] baseReq, IHttpService service) invoked but not implemented on class "+this.name);
    }

    List<IScanIssue> doScan(IHttpRequestResponse baseRequestResponse) {
        return doScan(baseRequestResponse.getRequest(), baseRequestResponse.getHttpService());
    }

    boolean shouldScan(IHttpRequestResponse baseRequestResponse) {
        if (BulkUtilities.globalSettings.getBoolean("skip vulnerable hosts") && BulkScan.hostsToSkip.containsKey(baseRequestResponse.getHttpService().getHost())) {
            return false;
        }
        return true;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return doScan(baseRequestResponse.getRequest(), baseRequestResponse.getHttpService());
    }

    void setRequestMethod(ZgrabLoader loader) {
        this.loader = loader;
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }

    static void recordCandidateFound() {
        BulkScanLauncher.getTaskEngine().candidates.incrementAndGet();
    }

    static void recordFinding() {
        BulkScanLauncher.getTaskEngine().findings.incrementAndGet();
    }



    static void report(String title, String detail, Resp... requests) {
        report(title, detail, null, requests);
    }

    static void report(String title, String detail, HttpRequestResponse... requests) {
        report(title, detail, null, requests);
    }


    static void report(String title, String detail, byte[] baseBytes, HttpRequestResponse... requests) {
        ArrayList<Resp> responses = new ArrayList<>();
        for (HttpRequestResponse req: requests) {
            responses.add(new Resp(req));
        }

        report(title, detail, baseBytes, responses.toArray(new Resp[0]));
    }


    static void report(String title, String detail, byte[] baseBytes, Resp... requests) {
        recordFinding();
        IHttpRequestResponse base = requests[0].getReq();
        IHttpService service = base.getHttpService();

        ArrayList<IHttpRequestResponse> reqsToReport = new ArrayList<>();

        if (BulkUtilities.globalSettings.getBoolean("skip flagged hosts") && BulkScan.domainAlreadyFlagged(service)) {
            return;
        }

        if (BulkUtilities.globalSettings.getBoolean("flag new domains")) {
            if (!BulkScan.domainAlreadyFlagged(service)) {
                title = "NEW| " + title;
            }
        }

        if (baseBytes != null) {
            Resp baseReq = new Resp(new Req(baseBytes, null, service));
            reqsToReport.add(baseReq.getReq());
        }

        for (Resp request : requests) {
            reqsToReport.add(request.getReq());
        }

        if (BulkUtilities.isBurpPro()) {
            BulkUtilities.callbacks.addScanIssue(new CustomScanIssue(service, BulkUtilities.getURL(base.getRequest(), service), reqsToReport.toArray(new IHttpRequestResponse[0]), title, detail, "High", "Tentative", "."));
        } else {
            reportToOutput(title, service, detail, reqsToReport);
        }

        if (Utilities.globalSettings.getBoolean("report to organizer")) {
            reportToOrganiser(title, service, detail, reqsToReport);
        }
    }

    static void reportToOutput(String title, IHttpService service, String detail, ArrayList<IHttpRequestResponse> reqsToReport) {
        StringBuilder serialisedIssue = new StringBuilder();
        serialisedIssue.append("Found issue: ");
        serialisedIssue.append(title);
        serialisedIssue.append("\n");
        serialisedIssue.append("Target: ");
        serialisedIssue.append(service.getProtocol());
        serialisedIssue.append("://");
        serialisedIssue.append(service.getHost());
        serialisedIssue.append("\n");
        serialisedIssue.append(detail);
        serialisedIssue.append("\n");
        serialisedIssue.append("Evidence: \n======================================\n");
        for (IHttpRequestResponse req : reqsToReport) {
            serialisedIssue.append(BulkUtilities.helpers.bytesToString(req.getRequest()));
//                serialisedIssue.append("\n--------------------------------------\n");
//                if (req.getResponse() == null) {
//                    serialisedIssue.append("[no response]");
//                }
//                else {
//                    serialisedIssue.append(BulkUtilities.helpers.bytesToString(req.getResponse()));
//                }
            serialisedIssue.append("\n======================================\n");
        }

        BulkUtilities.out(serialisedIssue.toString());
    }

    static void reportToOrganiser(String title, IHttpService service, String detail, List<IHttpRequestResponse> reqsToReport) {
        for (IHttpRequestResponse req : reqsToReport) {
            HttpRequestResponse montoyaReq = Utilities.buildMontoyaResp(new Resp(req));
            montoyaReq.annotations().setNotes(title +"\n\n"+detail);
            BulkUtilities.montoyaApi.organizer().sendToOrganizer(montoyaReq);
            break;
        }
    }

    static Resp request(IHttpService service, byte[] req) {
        return request(service, req, 0);
    }

    static Resp request(IHttpService service, byte[] req, int maxRetries) {
        return request(service, req, maxRetries, false);
    }

    static Resp request(IHttpService service, byte[] req, int maxRetries, boolean forceHTTP1) {
        return request(service, req, maxRetries, forceHTTP1, null);
    }

    static HttpRequestResponse request(HttpRequest req, boolean forceHTTP1) {
        if (BulkUtilities.unloaded.get()) {
            throw new RuntimeException("Aborting due to extension unload");
        }

        HttpMode mode = HttpMode.AUTO;
        if (forceHTTP1) {
            mode = HttpMode.HTTP_1;
        }

        return Utilities.montoyaApi.http().sendRequest(req, mode);
    }

//    static Resp turboRequest(IHttpService service, byte[] req) {
//        throttle();
//        BulkUtilities.requestCount.incrementAndGet();
//        return TurboLib.request(service, req);
//    }

    static void throttle() {
        int throttle = BulkUtilities.globalSettings.getInt("per-thread throttle");
        if (throttle != 0) {
            try {
                Thread.sleep(throttle);
            } catch (InterruptedException e) {

            }
        }
    }

    static Resp request(IHttpService service, byte[] req, int maxRetries, boolean forceHTTP1, HashMap<String, Boolean> config) {
        if (BulkUtilities.unloaded.get()) {
            throw new RuntimeException("Aborting due to extension unload");
        }

//        if (Utilities.globalSettings.getBoolean("use turbo for requests")) {
//            return turboRequest(service, req);
//        }

        IHttpRequestResponse iRequestResponse = null;
        BulkUtilities.requestCount.incrementAndGet();
        long startTime = System.currentTimeMillis();
        long endTime = 0;
        int attempts = 0;
        while ((iRequestResponse == null || iRequestResponse.getResponse() == null) && attempts <= maxRetries) {

            try {
                byte[] responseBytes;
                if (forceHTTP1 || !BulkUtilities.supportsHTTP2) {
                    req = BulkUtilities.replaceFirst(req, "HTTP/2\r\n", "HTTP/1.1\r\n");
                }

                IHttpRequestResponse temp;
                throttle();
                if (BulkUtilities.supportsHTTP2) {
                    //responseBytes = BulkUtilities.callbacks.makeHttpRequest(service, req).getResponse();
                    startTime = System.currentTimeMillis();
                    temp = BulkUtilities.callbacks.makeHttpRequest(service, req, forceHTTP1);
                } else {
                    startTime = System.currentTimeMillis();
                    temp = BulkUtilities.callbacks.makeHttpRequest(service, req);
                }
                endTime = System.currentTimeMillis();
                responseBytes = temp.getResponse();
                iRequestResponse = new Req(req, responseBytes, service);
            } catch (NoSuchMethodError e) {
                BulkUtilities.supportsHTTP2 = false;
                continue;
            } catch (RuntimeException e) {
                BulkUtilities.err("Recovering from request exception: " + service.getHost() + ": "+e.getMessage());
            }
            attempts += 1;
        }

        if (iRequestResponse == null) {
            iRequestResponse = new Req(req, null, service);
        }

        if (endTime == 0) {
            endTime = System.currentTimeMillis();
        }

        return new Resp(iRequestResponse, startTime, endTime);
    }
}
