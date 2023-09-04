package burp;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;

class OfferBulkScan implements IContextMenuFactory {
    private List<Scan> scans;

    OfferBulkScan(List<Scan> scans) {
        this.scans = scans;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        IHttpRequestResponse[] reqs = invocation.getSelectedMessages();
        List<JMenuItem> options = new ArrayList<>();

        JMenu scanMenu = new JMenu(BulkUtilities.name);

        if (reqs != null && reqs.length > 0) {
            for (Scan scan : scans) {
                JMenuItem probeButton = new JMenuItem(scan.name);
                probeButton.addActionListener(new TriggerBulkScan(scan, reqs));
                scanMenu.add(probeButton);
            }
        } else if (invocation.getSelectedIssues().length > 0) {
            for (Scan scan : scans) {
                JMenuItem probeButton = new JMenuItem(scan.name);
                probeButton.addActionListener(new TriggerBulkScan(scan, invocation.getSelectedIssues(), false));
                scanMenu.add(probeButton);
            }

            if (invocation.getSelectedIssues()[0].getIssueName().contains("Secret input: header")) {
                for (Scan scan : scans) {
                    if (! (scan instanceof ParamScan)) {
                        continue;
                    }
                    JMenuItem probeButton = new JMenuItem("Mined: "+scan.name);
                    probeButton.addActionListener(new TriggerBulkScan(scan, invocation.getSelectedIssues(), true));
                    scanMenu.add(probeButton);
                }
            }
        }

        options.add(scanMenu);
        return options;
    }
}
