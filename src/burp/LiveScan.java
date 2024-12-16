package burp;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.organizer.Organizer;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

import static burp.BulkScan.shouldFilter;

public class LiveScan implements HttpHandler {

    ConcurrentHashMap<Integer, Boolean> scannedKeys = new ConcurrentHashMap<>();

    public LiveScan() {

    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent httpRequestToBeSent) {
        return RequestToBeSentAction.continueWith(httpRequestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived httpResponseReceived) {
        scan(httpResponseReceived);
        return ResponseReceivedAction.continueWith(httpResponseReceived);
    }

    private void scan(HttpResponseReceived response) {
        if (!Utilities.globalSettings.getBoolean("live scan")) {
            return;
        }

        if (!Utilities.montoyaApi.scope().isInScope(response.initiatingRequest().url())) {
            return;
        }

        if (Scan.getLastScan() == null) {
            Utilities.out("Not initiating a live scan - configure & launch a manual scan first");
        }

        HttpService service = response.initiatingRequest().httpService();
        IHttpService oldService = Utilities.helpers.buildHttpService(service.host(), service.port(), service.secure());
        IHttpRequestResponse req = new Req(response.initiatingRequest().toByteArray().getBytes(), response.toByteArray().getBytes(), oldService);
        ScanItem item = new ScanItem(req, Utilities.globalSettings, Scan.getLastScan());
        if (shouldFilter(item)) {
            return;
        }

        if (Utilities.globalSettings.getBoolean("use key")) {
            String key = item.getKey();
            Boolean alreadySeen = scannedKeys.putIfAbsent(key.hashCode(), true);
            if (alreadySeen != null) {
                return;
            }
        }

        Thread.ofVirtual().start(() -> {
            new BulkScanItem(item.scan, item, System.currentTimeMillis()).run();
        });
    }
}


