package burp;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;

import burp.api.montoya.core.ByteArray;


class PayloadInjector {

    public IHttpService getService() {
        return service;
    }

    private IHttpService service;

    public IScannerInsertionPoint getInsertionPoint() {
        return insertionPoint;
    }

    private IScannerInsertionPoint insertionPoint;

    public Object getBase() {
        return base;
    }

    private Object base;

    PayloadInjector(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        this.service = baseRequestResponse.getHttpService();
        this.base = baseRequestResponse;
        this.insertionPoint = insertionPoint;
    }

    PayloadInjector(WebSocketMessageImpl base) {
        this.base = base;
        this.service = null;
        this.insertionPoint = null;
    }

    ArrayList<Attack> fuzz(Attack baselineAttack, Probe probe) {
        return fuzz(baselineAttack, probe, null);
    }

    // fixme horribly inefficient
    ArrayList<Attack> fuzz(Attack baselineAttack, Probe probe, String mutation) {
        ArrayList<Attack> attacks = new ArrayList<>(2);
        Attack breakAttack = buildAttackFromProbe(probe, probe.getNextBreak(), mutation);

        if (BulkUtilities.identical(baselineAttack, breakAttack)) {
            return new ArrayList<>();
        }

        for(int k=0; k<probe.getNextEscapeSet().length; k++) {
            Attack benignAttack = buildAttackFromProbe(probe, probe.getNextEscapeSet()[k], mutation);
            benignAttack.addAttack(baselineAttack);
            if(!BulkUtilities.identical(benignAttack, breakAttack)) {
                attacks = verify(benignAttack, breakAttack, probe, k, mutation);
                if (!attacks.isEmpty()) {
                    break;
                }
            }
        }

        return attacks;
    }

    private ArrayList<Attack> verify(Attack doNotBreakAttackSeed, Attack breakAttackSeed, Probe probe, int chosen_escape) {
        return verify(doNotBreakAttackSeed, breakAttackSeed, probe, chosen_escape, null);
    }

    private ArrayList<Attack> verify(Attack doNotBreakAttackSeed, Attack breakAttackSeed, Probe probe, int chosen_escape, String mutation) {
        ArrayList<Attack> attacks = new ArrayList<>(2);
        Attack mergedBreakAttack = new Attack();
        mergedBreakAttack.addAttack(breakAttackSeed);
        Attack mergedDoNotBreakAttack = new Attack();
        mergedDoNotBreakAttack.addAttack(doNotBreakAttackSeed);

        Attack tempDoNotBreakAttack = doNotBreakAttackSeed;

        int confirmations = BulkUtilities.globalSettings.getInt("confirmations");
        boolean boostedConfirmations = false;
        for(int i=0; i<confirmations; i++) {
            Attack tempBreakAttack = buildAttackFromProbe(probe, probe.getNextBreak(), mutation);
            mergedBreakAttack.addAttack(tempBreakAttack);

            if( BulkUtilities.similar(mergedDoNotBreakAttack, tempBreakAttack) || (probe.getRequireConsistentEvidence() && BulkUtilities.similarIsh(mergedDoNotBreakAttack, mergedBreakAttack, tempDoNotBreakAttack, tempBreakAttack))) {
                return new ArrayList<>();
            }

            if (boostedConfirmations && mergedDoNotBreakAttack.size() > mergedBreakAttack.size()+5) {
                continue;
            }

            tempDoNotBreakAttack = buildAttackFromProbe(probe, probe.getNextEscapeSet()[chosen_escape], mutation);
            mergedDoNotBreakAttack.addAttack(tempDoNotBreakAttack);

            if( BulkUtilities.similar(mergedBreakAttack, tempDoNotBreakAttack) || (probe.getRequireConsistentEvidence() && BulkUtilities.similarIsh(mergedDoNotBreakAttack, mergedBreakAttack, tempDoNotBreakAttack, tempBreakAttack))) {
                return new ArrayList<>();
            }

            if (i == confirmations-1 && !boostedConfirmations) {
                HashSet<String> keys =  Attack.getNonMatchingPrints(mergedDoNotBreakAttack, mergedBreakAttack);
                if (tempBreakAttack.allKeysAreQuantitative(keys)) {
                    confirmations = BulkUtilities.globalSettings.getInt("quantitative confirmations");
                    boostedConfirmations = true;
                }
            }
        }

        // this final probe pair is sent out of order, to prevent alternation false positives
        tempDoNotBreakAttack = buildAttackFromProbe(probe, probe.getNextEscapeSet()[chosen_escape], mutation);
        mergedDoNotBreakAttack.addAttack(tempDoNotBreakAttack);
        Attack tempBreakAttack = buildAttackFromProbe(probe, probe.getNextBreak(), mutation);
        mergedBreakAttack.addAttack(tempBreakAttack);

        // point is to exploit response attributes that vary in "don't break" responses (but are static in 'break' responses)
        if(BulkUtilities.similarIsh(mergedDoNotBreakAttack, mergedBreakAttack, tempDoNotBreakAttack, tempBreakAttack)
                || (probe.getRequireConsistentEvidence() && BulkUtilities.similar(mergedBreakAttack, tempDoNotBreakAttack))) {
            return new ArrayList<>();
        }

        if (!boostedConfirmations) {
            HashSet<String> keys = Attack.getNonMatchingPrints(mergedDoNotBreakAttack, mergedBreakAttack);
            if (tempBreakAttack.allKeysAreQuantitative(keys)) {
                return new ArrayList<>();
            }
        }

        attacks.add(mergedBreakAttack);
        attacks.add(mergedDoNotBreakAttack);

        return attacks;
    }


    private Attack buildAttackFromProbe(Probe probe, String payload) {
        return buildAttackFromProbe(probe, payload, null);
    }

    private Attack buildAttackFromProbe(Probe probe, String payload, String mutation) {
        boolean randomAnchor = probe.getRandomAnchor();
        byte prefix = probe.getPrefix();

        String anchor = "";
        if (randomAnchor) {
            anchor = BulkUtilities.generateCanary();
        }
        //else {
        //    payload = payload.replace("z", BulkUtilities.generateCanary());
        //}

        if (this.base instanceof IHttpRequestResponse) {
            String base_payload = payload;
            if (prefix == Probe.PREPEND) {
                payload += insertionPoint.getBaseValue();
            }
            else if (prefix == Probe.APPEND) {
                payload = insertionPoint.getBaseValue() + anchor + payload;
            }
            else if (prefix == Probe.REPLACE) {
                // payload = payload;
            }
            else {
                BulkUtilities.err("Unknown payload position");
            }
            boolean needCacheBuster = probe.useCacheBuster() || insertionPoint.getInsertionPointType() == IScannerInsertionPoint.INS_PARAM_COOKIE || insertionPoint.getInsertionPointType() == IScannerInsertionPoint.INS_HEADER || insertionPoint.getInsertionPointType() == IScannerInsertionPoint.INS_EXTENSION_PROVIDED;

            Resp req = buildRequest(payload, needCacheBuster, mutation);
            if(randomAnchor) {
                req.setHighlight(anchor);
                //req = BulkUtilities.highlightRequestResponse(req, anchor, anchor, insertionPoint);
            }
   
            return new Attack(req, probe, base_payload, anchor);
        } else if (this.base instanceof WebSocketMessageImpl) {
            String base_payload = payload;
            WebSocketMessageImpl baseCast = (WebSocketMessageImpl) base;
            String base_message = baseCast.payload().toString();
            int startI = base_message.indexOf("FU");
            int endI = base_message.indexOf("ZZ");
            String baseValue = base_message.substring(startI + 2, endI);
        
            // i did implement this using regex first, however somehow it broke the fuzzing
            // this logic might appear slight different from the original, but it does the same
            // but since i couldn't call or write a buldRequest method, this does something similar
            if (prefix == Probe.PREPEND) {
                payload = base_message.substring(0, startI + 2) + payload + baseValue + base_message.substring(endI);
            }
            else if (prefix == Probe.APPEND) {
                payload = base_message.substring(0, startI + 2) + baseValue + anchor + payload + base_message.substring(endI);
            }
            else if (prefix == Probe.REPLACE) {
                // payload = payload;
            } else {
                BulkUtilities.err("Unknown payload position");
            }
        
            // no need for cache buster
            WebSocketMessageImpl req = new WebSocketMessageImpl(ByteArray.byteArray(payload), baseCast.direction(), baseCast.upgradeRequest(), baseCast.annotations(), BulkUtilities.globalSettings.getInt("ws: timeout"));

            return new Attack(req, probe, base_payload, anchor);
        } else {
            throw new IllegalArgumentException("Unsupported base type: " + this.base.getClass().getName());
        }
    }

    Resp buildRequest(String payload, boolean needCacheBuster) {
        return buildRequest(payload, needCacheBuster, null);
    }

    Resp buildRequest(String payload, boolean needCacheBuster, String mutation) {

        byte[] request = insertionPoint.buildRequest(payload.getBytes());

        if (needCacheBuster) {
            request = BulkUtilities.addCacheBuster(request, BulkUtilities.generateCanary());
        }

        boolean forceHttp1 = false;
        if (mutation != null) {
            forceHttp1 = true;
            HeaderMutator mutator = new HeaderMutator();
            try {
                byte[] newRequest = mutator.mutateRequest(request, mutation, payload.split("\\|"));
                request = newRequest;
            } catch (IOException e) {
                BulkUtilities.out(e.toString());
            }
        }

        Resp requestResponse = burp.Scan.request(service, request, 0, forceHttp1);
        //BulkUtilities.out("Payload: "+payload+"|"+baseRequestResponse.getHttpService().getHost());

        return requestResponse;// BulkUtilities.buildRequest(baseRequestResponse, insertionPoint, payload)
    }

    Attack probeAttack(String payload) {
        return probeAttack(payload, null);
    }

    Attack probeAttack(String payload, String mutation) {
        byte[] request = insertionPoint.buildRequest(payload.getBytes());

        //IParameter cacheBuster = burp.BulkUtilities.helpers.buildParameter(BulkUtilities.generateCanary(), "1", IParameter.PARAM_URL);
        //request = burp.BulkUtilities.helpers.addParameter(request, cacheBuster);
        //request = burp.BulkUtilities.appendToQuery(request, BulkUtilities.generateCanary()+"=1");
        request = BulkUtilities.addCacheBuster(request, BulkUtilities.generateCanary());

        boolean forceHttp1 = false;
        if (mutation != null) {
            forceHttp1 = true;
            HeaderMutator mutator = new HeaderMutator();
            try {
                byte[] newRequest = mutator.mutateRequest(request, mutation, payload.split("\\|"));
                request = newRequest;
            } catch (java.io.IOException e) {
                //BulkUtilities.out("ERROR: failed to mutate request: " + e.toString());
            }
        }

        Resp requestResponse = Scan.request(service, request, 0, forceHttp1);
        return new Attack(requestResponse, null, null, "");
    }


    Attack buildAttack(String payload, boolean random) {
        String canary = "";

        if (this.base instanceof IHttpRequestResponse) {
            if (random) {
            canary = BulkUtilities.generateCanary();
            }

            return new Attack(buildRequest(canary+payload, !random), null, null, canary);
        } else if (this.base instanceof WebSocketMessageImpl) {
            ByteArray fPayload;

            WebSocketMessageImpl baseCast = (WebSocketMessageImpl) base;
            String baseMessageString = baseCast.payload().toString();
            int startI = baseMessageString.indexOf("FU");
            int endI = baseMessageString.indexOf("ZZ");

            String modifiedMessage;

            if (random) {
                canary = BulkUtilities.generateCanary();

                modifiedMessage = baseMessageString.substring(0, startI) + canary + payload + baseMessageString.substring(endI + 2);
                fPayload = ByteArray.byteArray(modifiedMessage);
            } else {
                modifiedMessage = baseMessageString.substring(0, startI) + payload + baseMessageString.substring(endI + 2);
                fPayload = ByteArray.byteArray(modifiedMessage);
            }

            WebSocketMessageImpl request = new WebSocketMessageImpl(fPayload, baseCast.direction(), baseCast.upgradeRequest(), baseCast.annotations(), BulkUtilities.globalSettings.getInt("ws: timeout"));

            return new Attack(request);
        } else {
            throw new IllegalArgumentException("Unsupported base type: " + this.base.getClass().getName());
        }
    }

}
