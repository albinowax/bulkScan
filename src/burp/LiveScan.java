package burp;

import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.organizer.Organizer;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;

public class LiveScan implements HttpHandler {

    HashSet<String> observedKeys = new HashSet<>();

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
        // todo import filter system - split into small static methods
        // apply filters
//        Calculate key
//        Check observedKeys
//        Update observedKeys
//        Queue ScanItem / Launch vthread
// new BulkScanItem(scan, req, start).execute()
        Thread.ofVirtual().start(() -> {
            // do the work
        });
    }
}


