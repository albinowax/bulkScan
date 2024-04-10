package burp;

import java.util.*;

public class QuantitativeMeasurements {
    ArrayList<Long> measurements;
    String key;

    public QuantitativeMeasurements(String key) {
        measurements = new ArrayList<>();
        this.key = key;
    }

    public QuantitativeMeasurements(Resp resp) {
        measurements = new ArrayList<>();
        measurements.add(resp.getAttribute(key));
    }

    void updateWith(Resp resp) {
        measurements.add(resp.getAttribute(key));
        Collections.sort(measurements);
    }

    void merge(QuantitativeMeasurements newMeasurements) {
        measurements.addAll(newMeasurements.measurements);
        Collections.sort(measurements);
    }

    @Override
    public String toString() {
        return measurements.toString();
    }

    private boolean basicOverlap(QuantitativeMeasurements o) {
        int OFFSET = 0;
        return Collections.min(o.measurements) < Collections.max(measurements)+OFFSET &&
                Collections.max(o.measurements) > Collections.min(measurements)-OFFSET;
    }

    public String quantileRange() {
        return measurements.get(0) + "-" + getQuantileTop(measurements);
    }

    private boolean quantileOverlap(QuantitativeMeasurements compareMeasurements) {
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
        boolean ret = quantileOverlap((QuantitativeMeasurements)o);
        return ret;
    }

}
