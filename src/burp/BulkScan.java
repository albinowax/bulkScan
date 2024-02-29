package burp;

import org.apache.commons.collections4.queue.CircularFifoQueue;
import org.apache.commons.lang3.NotImplementedException;
import org.apache.commons.lang3.StringUtils;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URL;
import java.util.*;
import java.util.concurrent.*;

import static java.lang.Math.min;
import static org.apache.commons.lang3.math.NumberUtils.max;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

class BulkScan implements Runnable  {
    private IHttpRequestResponse[] reqs;
    private Scan scan;
    private boolean useMinedHeader = false;
    private ConfigurableSettings config;
    public static List<Scan> scans = new ArrayList<>();
    static ConcurrentHashMap<String, Boolean> hostsToSkip = new ConcurrentHashMap<>();

    BulkScan(Scan scan, IHttpRequestResponse[] reqs, ConfigurableSettings config) {
        this.scan = scan;
        this.reqs = reqs;
        this.config = config;
    }

    BulkScan(Scan scan, IHttpRequestResponse[] reqs, ConfigurableSettings config, boolean useMinedHeader) {
        this.scan = scan;
        this.reqs = reqs;
        this.config = config;
        this.useMinedHeader = useMinedHeader;
    }

    // this uses hostsToSkip as a cache to avoid hitting the sitemap so much
    static boolean domainAlreadyFlagged(IHttpService service) {
        if (domainAlreadyFlaggedInThisScan(service)) {
            return true;
        }
        if (BulkUtilities.callbacks.getScanIssues(service.getProtocol()+"://"+service.getHost()).length > 0) {
            BulkScan.hostsToSkip.put(service.getHost(), true);
            return true;
        }

        return false;
    }

    static boolean domainAlreadyFlaggedInThisScan(IHttpService service) {
        return BulkScan.hostsToSkip.containsKey(service.getHost());
    }

    public void run() {
        try {
            long start = System.currentTimeMillis();
            ScanPool taskEngine = BulkScanLauncher.getTaskEngine();

            int queueSize = taskEngine.getQueue().size();
            BulkUtilities.log("Adding " + reqs.length + " tasks to queue of " + queueSize);
            queueSize += reqs.length;
            int thread_count = taskEngine.getCorePoolSize();


            //ArrayList<IHttpRequestResponse> reqlist = new ArrayList<>(Arrays.asList(reqs));

            ArrayList<ScanItem> reqlist = new ArrayList<>();

            for (IHttpRequestResponse req : reqs) {
                if (req == null || req.getRequest() == null) {
                    BulkUtilities.out("Skipping null request - not sure how that got there");
                    continue;
                }
//
//                if (reqs.length > 10000 && req.getResponse().length > 500000) {
//                    continue;
//                }

                reqlist.add(new ScanItem(req, config, scan));
            }

            Collections.shuffle(reqlist);
            Collections.sort(reqlist, new SortByParentDomain());

            int cache_size = queueSize; //thread_count;

            Set<String> keyCache = new HashSet<>();

            Queue<String> cache = new CircularFifoQueue<>(cache_size);
            HashSet<String> remainingHosts = new HashSet<>();

            int i = 0;
            int queued = 0;
            int totalRequests = reqlist.size();
            String filter = BulkUtilities.globalSettings.getString("filter");
            String respFilter = BulkUtilities.globalSettings.getString("resp-filter");
            boolean applyRespFilter = !"".equals(respFilter);
            boolean applyFilter = !"".equals(filter);
            String mimeFilter = BulkUtilities.globalSettings.getString("mimetype-filter");
            boolean applyMimeFilter = !"".equals(mimeFilter);
            boolean applySchemeFilter = config.getBoolean("filter HTTP");

            // every pass adds at least one item from every host
            while (!reqlist.isEmpty()) {
                BulkUtilities.out("Loop " + i++);
                ListIterator<ScanItem> left = reqlist.listIterator();
                while (left.hasNext()) {
                    if (BulkUtilities.unloaded.get()) {
                        throw new InterruptedException("Unloaded during queue");
                    }

                    ScanItem req = left.next();

                    if (applySchemeFilter && "http".equals(req.req.getHttpService().getProtocol())) {
                        left.remove();
                        continue;
                    }

//                    if (BulkUtilities.globalSettings.getBoolean("skip flagged hosts") && domainAlreadyFlagged(req.req.getHttpService())) {
//                        continue;
//                    }

                    if (applyFilter && !BulkUtilities.containsBytes(req.req.getRequest(), filter.getBytes())) {
                        left.remove();
                        continue;
                    }

                    if (applyMimeFilter) {
                        byte[] resp = req.req.getResponse();
                        if (resp == null) {
                            if (!BulkUtilities.getHeader(req.req.getRequest(), "Accept").toLowerCase().contains(mimeFilter)) {
                                left.remove();
                                continue;
                            }
                        } else {
                            if (!BulkUtilities.getHeader(req.req.getResponse(), "Content-Type").toLowerCase().contains(mimeFilter)) {
                                left.remove();
                                continue;
                            }
                        }
                    }

                    // fixme doesn't actually work - maybe the resp is always null?
                    if (applyRespFilter) {
                        byte[] resp = req.req.getResponse();
                        if (resp == null || !BulkUtilities.containsBytes(resp, respFilter.getBytes())) {
                            BulkUtilities.log("Skipping request due to response filter");
                            left.remove();
                            continue;
                        }
                    }

                    String host = req.host;
                    if (cache.contains(host)) {
                        remainingHosts.add(host);
                        continue;
                    }


                    if (scan instanceof ParamScan && !req.prepared()) {
                        ArrayList<ScanItem> newItems = req.prepare(useMinedHeader);

                        // remove the raw request - we'll add it back after
                        left.remove();

                        for (ScanItem item : newItems) {
                            String key = item.getKey();
                            if (!keyCache.contains(key)) {
                                left.add(item);
                            }
                        }

                        // re-queue the raw request
                        // I'm confused
                        left.add(req);
                        req = left.previous();
                        continue;
                    }

                    if (config.getBoolean("use key")) {
                        String key = req.getKey();
                        if (keyCache.contains(key)) {
                            left.remove();
                            continue;
                        }
                        keyCache.add(key);
                    }

                    if (req.insertionPoint == null && !scan.supportsRequestScan()) {
                        left.remove();
                        continue;
                    }

                    cache.add(host);
                    BulkUtilities.log("Adding request on " + host + " to queue");
                    queued++;
                    taskEngine.execute(new BulkScanItem(scan, req, start));
                }

                cache = new CircularFifoQueue<>(max(min(remainingHosts.size() - 1, thread_count), 1));
            }

            BulkUtilities.out("Queued " + queued + " attacks from " + totalRequests + " requests in " + (System.currentTimeMillis() - start) / 1000 + " seconds");
        } catch (Exception e) {
            BulkUtilities.out("Queue aborted due to exception");
            BulkUtilities.showError(e);
        }
    }
}


