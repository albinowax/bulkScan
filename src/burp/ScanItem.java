package burp;

import java.util.ArrayList;
import java.util.Arrays;

class ScanItem {
    private Scan scan;
    IHttpRequestResponse req;
    String host;
    private ConfigurableSettings config;
    private boolean prepared = false;
    IScannerInsertionPoint insertionPoint;
    private IParameter param;
    private String key = null;
    String method = null;


    ScanItem(IHttpRequestResponse req, ConfigurableSettings config, Scan scan) {
        this.req = req;
        this.host = req.getHttpService().getHost();
        this.config = config;
        this.scan = scan;
    }

    ScanItem(IHttpRequestResponse req, ConfigurableSettings config, Scan scan, IParameter param, IScannerInsertionPoint insertionPoint) {
        this.req = req;
        this.config = config;
        this.scan = scan;
        this.insertionPoint = insertionPoint;
        this.host = req.getHttpService().getHost();
        this.prepared = true;
        this.param = param;
    }

    ScanItem(IHttpRequestResponse req, ConfigurableSettings config, Scan scan, IParameter param) {
        this.req = req;
        this.host = req.getHttpService().getHost();
        this.config = config;
        this.param = param;
        insertionPoint = new RawInsertionPoint(req.getRequest(), param.getName(), param.getValueStart(), param.getValueEnd(), param.getType(), param.getValue());
        this.prepared = true;
        this.scan = scan;
    }

    boolean prepared() {
        return prepared;
    }

    ArrayList<ScanItem> prepare(boolean useMinedHeader) {
        ArrayList<ScanItem> items = new ArrayList<>();

        method = BulkUtilities.getMethod(req.getRequest());
        prepared = true;

        if (useMinedHeader) {
            byte[] reqBytes = req.getRequest();
            int[] offets = Utilities.getHeaderOffsets(reqBytes, "TCZqBcS13SA8QRCpW");
            if (offets == null) {
                return items;
            }

            int nameStart = offets[2]+2;
            int valueStart = nameStart;
            while (reqBytes[valueStart] != ' ') {
                valueStart++;
            }
            valueStart--;
            //valueStart--;
            String name = new String(Arrays.copyOfRange(reqBytes, nameStart, valueStart));
            int valueEnd = valueStart;
            while (reqBytes[valueEnd] != '\r') {
                valueEnd++;
            }
            //valueEnd--;
            String value = new String(Arrays.copyOfRange(reqBytes, valueStart+2, valueEnd));
            //Utilities.out("Name: '"+name+"' Value: '"+value+"'");
            PartialParam headerInjectionPoint = new PartialParam(name, valueStart+2, valueEnd);
            items.add(new ScanItem(req, config, scan, headerInjectionPoint));
            return items;
        }

        // todo we kinda need the base-value
        if (BulkUtilities.containsBytes(req.getResponse(), "HTTP/2".getBytes())) {
            if (BulkUtilities.globalSettings.getBoolean("params: scheme")) {
                byte[] updated = BulkUtilities.addOrReplaceHeader(req.getRequest(), ":scheme", "m838jacxka");
                Req newReq = new Req(updated, req.getResponse(), req.getHttpService());
                items.add(new ScanItem(newReq, config, scan, BulkUtilities.paramify(updated, "scheme-proto", "m838jacxka", "https")));
            }

            if (BulkUtilities.globalSettings.getBoolean("params: scheme-path")) {
                byte[] updated = BulkUtilities.addOrReplaceHeader(req.getRequest(), ":scheme", "https://" + req.getHttpService().getHost() + "/m838jacxka");
                Req newReq = new Req(updated, req.getResponse(), req.getHttpService());
                items.add(new ScanItem(newReq, config, scan, BulkUtilities.paramify(updated, "scheme-path", "m838jacxka", "m838jacxka")));
            }

            if (BulkUtilities.globalSettings.getBoolean("params: scheme-host")) {
                byte[] updated = BulkUtilities.addOrReplaceHeader(req.getRequest(), ":scheme", "https://m838jacxka/");
                Req newReq = new Req(updated, req.getResponse(), req.getHttpService());
                items.add(new ScanItem(newReq, config, scan, BulkUtilities.paramify(updated, "scheme-host", "m838jacxka", "m838jacxka")));
            }
        }

        if (BulkUtilities.globalSettings.getBoolean("params: xff")) {
            //String fakeIP = "demo."+req.getHttpService().getHost();
            String fakeIP = "8.8.8.8";
            byte[] updated = BulkUtilities.addOrReplaceHeader(req.getRequest(), "X-Forwarded-For", fakeIP);
            Req newReq = new Req(updated, req.getResponse(), req.getHttpService());
            items.add(new ScanItem(newReq, config, scan, BulkUtilities.paramify(updated, "XFF", fakeIP, fakeIP)));
        }

        // scan the path, but only if there's no extension
        if (BulkUtilities.globalSettings.getBoolean("params: rest")) {
            String finalPathValue = ScanItem.getFinalFolder(req.getRequest());
            if (!"".equals(finalPathValue)) {
                String fakeValue = "kdlodjalszz";
                String path = Utilities.getPathFromRequest(req.getRequest());
                byte[] updated;
                if (path.contains(finalPathValue+" ")) {
                    updated = Utilities.replaceFirst(req.getRequest(), finalPathValue+" ", fakeValue+" ");
                } else {
                    updated = Utilities.replaceFirst(req.getRequest(), finalPathValue+"?", fakeValue+"?");
                }
                Req newReq = new Req(updated, req.getResponse(), req.getHttpService());
                items.add(new ScanItem(newReq, config, scan, BulkUtilities.paramify(updated, "path", fakeValue, finalPathValue)));
            }
        }

        // fixme analyzeRequest is really slow, should implement this stuff myself
        boolean cookiesToScan = BulkUtilities.globalSettings.getBoolean("params: cookie") && !"".equals(BulkUtilities.getHeader(req.getRequest(), "Cookie"));
        boolean bodyToScan = BulkUtilities.globalSettings.getBoolean("params: body") && !"".equals(BulkUtilities.getBody(req.getRequest()));
        if (cookiesToScan || bodyToScan) {
            ArrayList<IParameter> fancyParams = new ArrayList<>(BulkUtilities.helpers.analyzeRequest(req).getParameters());
            for (IParameter param : fancyParams) {
                byte type = param.getType();
                switch (type) {
                    case IParameter.PARAM_COOKIE:
                        if (cookiesToScan) {
                            break;
                        }
                        continue;
                    case IParameter.PARAM_BODY:
                        if (bodyToScan) {
                            break;
                        }
                    default:
                        continue;
                }
                IScannerInsertionPoint insertionPoint = new ParamInsertionPoint(req.getRequest(), param);
                items.add(new ScanItem(req, config, scan, param, insertionPoint));
            }
        }

        if (!BulkUtilities.globalSettings.getBoolean("params: query")) {
            return items;
        }

        // don't waste time analysing GET requests with no = in the request line
        // todo check method here once POST params are supported
        if (!BulkUtilities.getPathFromRequest(req.getRequest()).contains("=")) {
            if (!BulkUtilities.globalSettings.getBoolean("params: dummy")) {
                return items;
            }

            // if you use setRequest instead, it will overwrite the original!
            // fixme somehow triggers a stackOverflow
        }

        if (BulkUtilities.globalSettings.getBoolean("params: dummy")) {
            req = new Req(BulkUtilities.appendToQuery(req.getRequest(), BulkUtilities.globalSettings.getString("dummy param name") + "=z"), req.getResponse(), req.getHttpService());
        }

        ArrayList<PartialParam> params = BulkUtilities.getQueryParams(req.getRequest());

        for (IParameter param : params) {
            if (param.getType() != IParameter.PARAM_URL) {
                continue;
            }
            items.add(new ScanItem(req, config, scan, param, new ParamInsertionPoint(req.getRequest(), param)));
        }
        //req.getRequest(), param.getName(), param.getValueStart(), param.getValueEnd(), param.getType()
        return items;
    }

    String getKey() {

        if (method == null) {
            method = BulkUtilities.getMethod(req.getRequest());
        }

        if (key != null) {
            return key;
        }

        StringBuilder key = new StringBuilder();
        if (!config.getBoolean("filter HTTP")) {
            key.append(req.getHttpService().getProtocol());
        }

        key.append(req.getHttpService().getHost());

        if (param != null && scan instanceof ParamScan && config.getBoolean("key input name")) {
            key.append(param.getName());
            key.append(param.getType());
        }

        if (config.getBoolean("key method")) {
            key.append(method);
        }

        if (config.getBoolean("key path")) {
            key.append(BulkUtilities.getPathFromRequest(req.getRequest()).split("[?]", 1)[0]);
        }

        if (req.getResponse() == null && config.getBoolean("key content-type")) {
            key.append(BulkUtilities.getExtension(req.getRequest()));
        }

        if (req.getResponse() != null && (config.getBoolean("key header names") || config.getBoolean("key status") || config.getBoolean("key content-type") || config.getBoolean("key server"))) {
            IResponseInfo respInfo = BulkUtilities.helpers.analyzeResponse(req.getResponse());

            if (config.getBoolean("key header names")) {
                StringBuilder headerNames = new StringBuilder();
                for (String header : respInfo.getHeaders()) {
                    headerNames.append(header.split(": ")[0]);
                }
                key.append(headerNames.toString());
            }

            if (config.getBoolean("key status")) {
                key.append(respInfo.getStatusCode());
            }

            if (config.getBoolean("key content-type")) {
                key.append(respInfo.getStatedMimeType());
            }

            if (config.getBoolean("key server")) {
                key.append(BulkUtilities.getHeader(req.getResponse(), "Server"));
            }
        }

        this.key = key.toString();

        return this.key;
    }

    static String getFinalFolder(byte[] req) {
        if (!"".equals(Utilities.getExtension(req))) {
            return "";
        }

        String path = Utilities.getPathFromRequest(req).split("[?]")[0];
        if ("/".equals(path)) {
            return "";
        }

        String[] folders = path.split("/");
        if (folders.length < 3) {
            return "";
        }

        String folder = folders[folders.length-1];
        return folder;
    }

}
