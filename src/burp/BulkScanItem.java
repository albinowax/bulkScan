package burp;

class BulkScanItem implements Runnable {

    private final ScanItem baseItem;
    private final IHttpRequestResponse baseReq;
    private final Scan scanner;
    private final long start;

    BulkScanItem(Scan scanner, ScanItem baseReq, long start) {
        this.baseReq = baseReq.req; //BulkUtilities.callbacks.saveBuffersToTempFiles(baseReq.req);
        this.baseItem = baseReq;
        this.scanner = scanner;
        this.start = start;
    }

    public void run() {
        try {
            if (scanner.shouldScan(baseReq)) {
                if (baseItem.insertionPoint != null) {
                    Scan.reportAllIssues(scanner.doActiveScan(baseReq, baseItem.insertionPoint));
                }
                else {
                    Scan.reportAllIssues(scanner.doScan(baseReq));
                }
            } else {
                BulkUtilities.out("Skipping already-confirmed-vulnerable host: " + baseItem.host);
            }
            ScanPool engine = BulkScanLauncher.getTaskEngine();
            long done = engine.getCompletedTaskCount() + 1;

            if (engine.getQueue().size() < 1000 || done % 100 == 0) {
                BulkUtilities.out("Completed request with key " + baseItem.getKey() + ": " + done + " of " + (engine.getQueue().size() + done) + " in " + (System.currentTimeMillis() - start) / 1000 + " seconds with " + BulkUtilities.requestCount.get() + " requests," + engine.candidates.get() + " candidates and " + engine.findings.get() + " findings ");
            }

            if (Utilities.globalSettings.getBoolean("infinite scan")) {
                Utilities.out("Re-queuing completed task for infinite scan");
                engine.execute(this);
            }
        } catch (Exception e) {
            BulkUtilities.showError(e);
        }
    }
}
