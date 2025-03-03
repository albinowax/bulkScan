package burp;

import java.util.*;

import burp.api.montoya.core.ByteArray;

public class FastResponseVariations implements IResponseVariations {
 
    HashMap<String, Integer> attributes;
    HashSet<String> invariantAttributes;
    HashSet<String> variantAttributes;

    // http
    public FastResponseVariations() {
        this.invariantAttributes = new HashSet<>(Arrays.asList(new String[]{"start", "code", "headers", "newlines", "spaces"}));
        this.variantAttributes = new HashSet<>();
    }

    // ws
    public FastResponseVariations(String type) {
        if ("ws".equalsIgnoreCase(type)) {
            this.invariantAttributes = new HashSet<>(Arrays.asList(new String[]{"messageCount", "messageTypes", "messageLengths", "spaces", "tags"}));
            this.variantAttributes = new HashSet<>();
        }
    }

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

    public void updateWith(WebSocketMessageImpl wsMessage) {
        if (attributes == null) {
            attributes = new HashMap<>();
            for (String key: invariantAttributes) {
                attributes.put(key, calculateAttribute(wsMessage, key));
            }
        } else {
            // relegate entries from invariant to variant if they don't match
            Iterator<String> iter = invariantAttributes.iterator();
            while (iter.hasNext()) {
                String key = iter.next();
                if (calculateAttribute(wsMessage, key) != attributes.get(key)) {
                    iter.remove();
                    variantAttributes.add(key);
                }
            }
        }
    }

    private int calculateAttribute(WebSocketMessageImpl wsMessage, String attribute) {
        switch (attribute) {
            case "messageCount":
                return wsMessage.responses().size();
            case "messageTypes":
                if (wsMessage.responseTypes().isEmpty()) return 0;

                // create a chronological sequence (e.g. TBTT)
                StringBuilder pattern = new StringBuilder();
                for (WebSocketMessageImpl.MessageType type : wsMessage.responseTypes()) {
                    pattern.append(type == WebSocketMessageImpl.MessageType.TEXT ? 'T' : 'B');
                }
                // workaround to get the result as number
                byte[] bytes = pattern.toString().getBytes();
                StringBuilder hex = new StringBuilder();
                for (byte b : bytes) {
                    hex.append(String.format("%02X", b));
                }
        
                return Integer.parseInt(hex.substring(0, Math.min(8, hex.length())), 16);
            case "messageLengths":
                if (wsMessage.responses().isEmpty()) return 0;
        
                // same workaround
                StringBuilder hexBuilder = new StringBuilder();
                for (ByteArray message : wsMessage.responses()) {
                    hexBuilder.append(String.format("%04X", message.length()));
                }
        
                return Integer.parseInt(hexBuilder.substring(0, Math.min(8, hexBuilder.length())), 16);
            case "spaces":
                if (wsMessage.responses().isEmpty()) return 0;

                // same workaround
                StringBuilder spaces = new StringBuilder();
                for (ByteArray message : wsMessage.responses()) {
                    spaces.append(String.format("%04X", BulkUtilities.byteCount(message.getBytes(), ' ', 0, message.length())));
                }

                return Integer.parseInt(spaces.substring(0, Math.min(8, spaces.length())), 16);
            case "tags":
                if (wsMessage.responses().isEmpty()) return 0;

                // same workaround
                StringBuilder tags = new StringBuilder();
                for (ByteArray message : wsMessage.responses()) {
                    tags.append(String.format("%04X", BulkUtilities.byteCount(message.getBytes(), '<', 0, message.length())));

                return Integer.parseInt(tags.substring(0, Math.min(8, tags.length())), 16);
                }
        }
        return -1;
    }

}
