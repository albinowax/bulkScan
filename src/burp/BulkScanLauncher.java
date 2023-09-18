package burp;

import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

class BulkScanLauncher {

    private static ScanPool taskEngine;

    BulkScanLauncher(List<Scan> scans) {
        taskEngine = buildTaskEngine();
        BulkUtilities.callbacks.registerContextMenuFactory(new OfferBulkScan(scans));
    }

    private static ScanPool buildTaskEngine() {
        BlockingQueue<Runnable> tasks;
        tasks = new LinkedBlockingQueue<>();

        BulkUtilities.globalSettings.registerSetting("thread pool size", 8, "The maximum number of threads this tool will spin up. This roughly correlates with the number of concurrent requests. Increasing this value will make attacks run faster, and use more computer resources.");
        BulkUtilities.globalSettings.registerSetting("canary", BulkUtilities.randomString(8), "Static canary string used for input reflection detection sometimes");
        // BulkUtilities.globalSettings.registerSetting("use turbo for requests", false, "Use the Turbo Intruder request engine instead of Burp's");
        ScanPool taskEngine = new ScanPool(BulkUtilities.globalSettings.getInt("thread pool size"), BulkUtilities.globalSettings.getInt("thread pool size"), 10, TimeUnit.MINUTES, tasks);
        BulkUtilities.globalSettings.registerListener("thread pool size", value -> {
            BulkUtilities.out("Updating active thread pool size to " + value);
            try {
                taskEngine.setCorePoolSize(Integer.parseInt(value));
                taskEngine.setMaximumPoolSize(Integer.parseInt(value));
            } catch (IllegalArgumentException e) {
                taskEngine.setMaximumPoolSize(Integer.parseInt(value));
                taskEngine.setCorePoolSize(Integer.parseInt(value));
            }
        });
        return taskEngine;
    }

    static ScanPool getTaskEngine() {
        return taskEngine;
    }
}
