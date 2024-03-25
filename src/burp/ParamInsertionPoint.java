package burp;

public class ParamInsertionPoint implements IScannerInsertionPoint {
    byte[] request;
    String name;
    String value;
    byte type;


    ParamInsertionPoint(byte[] request, IParameter param) {
        this.request = request;
        this.name = param.getName();
        this.type = param.getType();
        this.value = param.getValue();

        // fixme need to decode this first if it's a sketchy param
        if (type == INS_PARAM_URL) {
            value = Utilities.decodeParam(value);
        }
    }

    ParamInsertionPoint(byte[] request, String name, String value, byte type) {
        this.request = request;
        this.name = name;
        this.value = value;
        this.type = type;
    }

    String calculateValue(String unparsed) {
        return unparsed;
    }

    @Override
    public String getInsertionPointName() {
        return name;
    }

    @Override
    public String getBaseValue() {
        return value;
    }

    @Override
    public byte[] buildRequest(byte[] payload) {
        IParameter newParam = BulkUtilities.helpers.buildParameter(name, BulkUtilities.encodeParam(BulkUtilities.helpers.bytesToString(payload)), type);
        return BulkUtilities.helpers.updateParameter(request, newParam);
    }

    @Override
    public int[] getPayloadOffsets(byte[] payload) {
        //IParameter newParam = BulkUtilities.helpers.buildParameter(name, BulkUtilities.encodeParam(BulkUtilities.helpers.bytesToString(payload)), type);
        return new int[]{0, 0};
        //return new int[]{newParam.getValueStart(), newParam.getValueEnd()};
    }

    @Override
    public byte getInsertionPointType() {
        return type;
        // return IScannerInsertionPoint.INS_EXTENSION_PROVIDED;
    }
}
