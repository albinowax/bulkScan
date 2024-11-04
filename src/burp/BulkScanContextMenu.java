package burp;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.ui.contextmenu.AuditIssueContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;

import javax.swing.*;
import java.awt.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

class BulkScanContextMenu implements ContextMenuItemsProvider {
    private static String SECRET_INPUT_HEADER = "Secret input: header";
    private List<Scan> scans;

    BulkScanContextMenu(List<Scan> scans) {
        this.scans = scans;
    }

    private static IScanIssue convertToIScanIssue(AuditIssue auditIssue) {
        return new IScanIssue() {
            @Override
            public URL getUrl() {
                try {
                    return new URL(auditIssue.baseUrl());
                }catch (MalformedURLException ignored) {
                    return null;
                }
            }

            @Override
            public String getIssueName() {
                return auditIssue.name();
            }

            @Override
            public int getIssueType() {
                return 0;
            }

            @Override
            public String getSeverity() {
                return auditIssue.severity().name();
            }

            @Override
            public String getConfidence() {
                return auditIssue.confidence().name();
            }

            @Override
            public String getIssueBackground() {
                return "";
            }

            @Override
            public String getRemediationBackground() {
                return auditIssue.remediation();
            }

            @Override
            public String getIssueDetail() {
                return auditIssue.detail();
            }

            @Override
            public String getRemediationDetail() {
                return auditIssue.remediation();
            }

            @Override
            public IHttpRequestResponse[] getHttpMessages() {
                List<IHttpRequestResponse> messages = auditIssue.requestResponses().stream().map(BulkScanContextMenu::convertToIHttpRequestResponse).collect(Collectors.toList());
                IHttpRequestResponse[] reqArray = new IHttpRequestResponse[messages.size()];
                reqArray = messages.toArray(reqArray);
                return reqArray;
            }

            @Override
            public IHttpService getHttpService() {
                HttpService httpService = auditIssue.httpService();
                return BulkUtilities.callbacks.getHelpers().buildHttpService(httpService.host(), httpService.port(), httpService.secure());
            }
        };
    }
    private static IHttpRequestResponse convertToIHttpRequestResponse(HttpRequestResponse customHttpRequestResponse) {
        return new IHttpRequestResponse() {
            @Override
            public byte[] getRequest() {
                return customHttpRequestResponse.request() == null ? null : customHttpRequestResponse.request().toByteArray().getBytes();
            }

            @Override
            public void setRequest(byte[] message) {
            }

            @Override
            public byte[] getResponse() {
                return customHttpRequestResponse.response() == null ? null : customHttpRequestResponse.response().toByteArray().getBytes();
            }

            @Override
            public void setResponse(byte[] message) {
            }

            @Override
            public String getComment() {
                return "";
            }

            @Override
            public void setComment(String comment) {
            }

            @Override
            public String getHighlight() {
                return "";
            }


            @Override
            public void setHighlight(String color) {
            }

            @Override
            public IHttpService getHttpService() {
                return BulkUtilities.callbacks.getHelpers().buildHttpService(customHttpRequestResponse.httpService().host(),customHttpRequestResponse.httpService().port(),customHttpRequestResponse.httpService().secure());
            }

            @Override
            public void setHttpService(IHttpService httpService) {
            }
        };
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent contextMenuEvent) {
        List<Component> options = new ArrayList<>();
        JMenu scanMenu = new JMenu(BulkUtilities.name);

        if(contextMenuEvent.messageEditorRequestResponse().isPresent()) {
            MessageEditorHttpRequestResponse messageEditorHttpRequestResponse = contextMenuEvent.messageEditorRequestResponse().get();
            HttpRequestResponse requestResponse = messageEditorHttpRequestResponse.requestResponse();
            for (Scan scan : scans) {
                JMenuItem probeButton = new JMenuItem(scan.name);
                probeButton.addActionListener(new TriggerBulkScan(scan, new IHttpRequestResponse[] { convertToIHttpRequestResponse(requestResponse) }));
                scanMenu.add(probeButton);
            }
        } else {
            List<IHttpRequestResponse> reqs = contextMenuEvent.selectedRequestResponses().stream().map(BulkScanContextMenu::convertToIHttpRequestResponse).collect(Collectors.toList());
            for (Scan scan : scans) {
                JMenuItem negotiationItem = new JMenuItem(scan.name);
                IHttpRequestResponse[] reqArray = new IHttpRequestResponse[reqs.size()];
                reqArray = reqs.toArray(reqArray);
                negotiationItem.addActionListener(new TriggerBulkScan(scan, reqArray));
                scanMenu.add(negotiationItem);
            }
        }

        options.add(scanMenu);
        return options;
    }

    @Override
    public List<Component> provideMenuItems(AuditIssueContextMenuEvent event) {
        List<Component> options = new ArrayList<>();

        JMenu scanMenu = new JMenu(BulkUtilities.name);
        List<IScanIssue> issues = event.selectedIssues().stream().map(BulkScanContextMenu::convertToIScanIssue).collect(Collectors.toList());
        IScanIssue[] oldIssues = new IScanIssue[issues.size()];
        oldIssues = issues.toArray(oldIssues);
        if (!issues.isEmpty()) {
            for (Scan scan : scans) {
                JMenuItem probeButton = new JMenuItem(scan.name);
                probeButton.addActionListener(new TriggerBulkScan(scan, oldIssues, false));
                scanMenu.add(probeButton);
            }
            if (issues.get(0).getIssueName().contains(SECRET_INPUT_HEADER)) {
                for (Scan scan : scans) {
                    if (! (scan instanceof ParamScan)) {
                        continue;
                    }
                    JMenuItem probeButton = new JMenuItem("Mined: "+scan.name);
                    probeButton.addActionListener(new TriggerBulkScan(scan, oldIssues, true));
                    scanMenu.add(probeButton);
                }
            }
        }

        options.add(scanMenu);
        return options;
    }
}
