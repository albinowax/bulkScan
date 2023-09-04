package burp;

import java.util.*;

public class FastResponseVariations implements IResponseVariations {

    HashMap<String, Integer> attributes;
    HashSet<String> invariantAttributes = new HashSet<>(Arrays.asList(new String[]{"start", "code", "headers", "newlines", "spaces"}));
    HashSet<String> variantAttributes;

    @Override
    public List<String> getVariantAttributes() {
        return new ArrayList<>(variantAttributes);
    }

    @Override
    public List<String> getInvariantAttributes() {
        return new ArrayList<>(invariantAttributes);
    }

    @Override
    public int getAttributeValue(String s, int i) {
        if (i != 0) {
            throw new RuntimeException("Requested request not stored");
        }
        return attributes.get(s);
    }

    @Override
    public void updateWith(byte[]... bytes) {
        byte[] respBytes = bytes[0];
        if (attributes == null) {
            attributes = new HashMap<>();
            for (String key: invariantAttributes) {
                attributes.put(key, calculateAttribute(respBytes, key));
            }
        } else {
            // relegate entries from invariant to variant if they don't match
            Iterator<String> iter = invariantAttributes.iterator();
            while (iter.hasNext()) {
                String key = iter.next();
                if (calculateAttribute(respBytes, key) != attributes.get(key)) {
                    iter.remove();
                    variantAttributes.add(key);
                }
            }
        }
    }

    private int calculateAttribute(byte[] bytes, String attribute) {
        int bodyStart = BulkUtilities.getBodyStart(bytes);

        switch (attribute) {
            case "length":
                return bytes.length - bodyStart;
            case "start":
                return BulkUtilities.getStartType(bytes).hashCode();
            case "code":
                return BulkUtilities.getCode(bytes);
            case "headers":
                return BulkUtilities.byteCount(bytes, '\n', 0, bodyStart);
            case "newlines":
                return BulkUtilities.byteCount(bytes, '\n', bodyStart, bytes.length);
            case "spaces":
                return BulkUtilities.byteCount(bytes, ' ', bodyStart, bytes.length);
            case "tags":
                return BulkUtilities.byteCount(bytes, '<', bodyStart, bytes.length);
            case "equals":
                return BulkUtilities.byteCount(bytes, '=', bodyStart, bytes.length);
        }
        return -1;
    }

}
