package burp;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

class TriggerBulkScan implements ActionListener {

    private IHttpRequestResponse[] reqs;
    private IScanIssue[] issues;
    private Scan scan;
    private boolean scanMinedHeader = false;

    TriggerBulkScan(Scan scan, IHttpRequestResponse[] reqs) {
        this.scan = scan;
        this.reqs = reqs;
    }

    TriggerBulkScan(Scan scan, IScanIssue[] issues, boolean scanMinedHeader) {
        this.scan = scan;
        this.issues = issues;
        this.scanMinedHeader = scanMinedHeader;
    }

    public void actionPerformed(ActionEvent e) {
        if (this.reqs == null) {
            this.reqs = new IHttpRequestResponse[issues.length];
            for (int i = 0; i < issues.length; i++) {
                IScanIssue issue = issues[i];
                if (scanMinedHeader) {
                    if (!issue.getIssueName().contains("Secret input: header")) {
                        continue;
                    }
                    reqs[i] = issue.getHttpMessages()[1];
                } else {
                    reqs[i] = issue.getHttpMessages()[0];
                }
                //reqs[i] = new Req(BulkUtilities.helpers.buildHttpRequest(issue.getUrl()), null, issue.getHttpService());
            }
        }

        ConfigurableSettings config = BulkUtilities.globalSettings.showSettings(scan.scanSettings.getSettings());
        if (config != null) {
            BulkScan bulkScan = new BulkScan(scan, reqs, config, scanMinedHeader);
            (new Thread(bulkScan)).start();
        }
    }
}
