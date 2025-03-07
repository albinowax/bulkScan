package burp;

import java.util.*;

public class WsQuantitativeMeasurements {
    ArrayList<Long> measurements;
    String key;

    public WsQuantitativeMeasurements(String key) {
        measurements = new ArrayList<>();
        this.key = key;
    }

    public WsQuantitativeMeasurements(Resp resp) {
        measurements = new ArrayList<>();
        measurements.add(resp.getAttribute(key));
    }

    void updateWith(Resp resp) {
        measurements.add(resp.getAttribute(key));
        Collections.sort(measurements);
    }

    void updateWith(WebSocketMessageImpl resp) {
        measurements.add(resp.getAttribute(key));
        Collections.sort(measurements);
    }

    void merge(WsQuantitativeMeasurements newMeasurements) {
        measurements.addAll(newMeasurements.measurements);
        Collections.sort(measurements);
    }

    @Override
    public String toString() {
        return measurements.toString();
    }

    private boolean basicOverlap(WsQuantitativeMeasurements o) {
        int OFFSET = 0;
        return Collections.min(o.measurements) < Collections.max(measurements)+OFFSET &&
                Collections.max(o.measurements) > Collections.min(measurements)-OFFSET;
    }

    public String quantileRange() {
        return measurements.get(0) + "-" + getQuantileTop(measurements);
    }

    private boolean quantileOverlap(WsQuantitativeMeasurements compareMeasurements) {
        ArrayList<Long> compare = compareMeasurements.measurements;
        return compare.get(0) <= getQuantileTop(measurements) &&
                getQuantileTop(compare) >= measurements.get(0);
    }

    private Long getQuantileTop(ArrayList<Long> list) {
        int FACTOR = BulkUtilities.globalSettings.getInt("quantile factor");
        return list.get((int)Math.ceil((float)list.size()/FACTOR)-1);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        boolean ret = quantileOverlap((WsQuantitativeMeasurements)o);
        return ret;
    }

}
