package burp;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import burp.api.montoya.core.ByteArray;

import burp.api.montoya.ui.contextmenu.WebSocketMessage;

import java.util.regex.Pattern;
import java.util.regex.Matcher;

class WsPayloadInjector {
    
    public WebSocketMessageImpl getWebSocketMessage() {
        return base;
    }

    private WebSocketMessageImpl base;

    WsPayloadInjector(WebSocketMessageImpl base) {
        this.base = base;
    }

    ArrayList<WsAttack> fuzz(WsAttack baselineAttack, Probe probe) {
        return fuzz(baselineAttack, probe, null);
    }
    
    ArrayList<WsAttack> fuzz(WsAttack baselineAttack, Probe probe, String mutation) {
        ArrayList<WsAttack> attacks = new ArrayList<>(2);
        WsAttack breakAttack = buildAttackFromProbe(probe, probe.getNextBreak(), mutation);

        if (WsBulkUtilities.identical(baselineAttack, breakAttack)) {
            return new ArrayList<>();
        }

        for (int k=0; k < probe.getNextEscapeSet().length; k++) {
            WsAttack benignAttack = buildAttackFromProbe(probe, probe.getNextEscapeSet()[k], mutation);
            benignAttack.addAttack(baselineAttack);
            if (!WsBulkUtilities.identical(benignAttack, breakAttack)) {
                attacks = verify(benignAttack, breakAttack, probe, k, mutation);
                if (!attacks.isEmpty()) {
                    break;
                }
            }
        }
        
        return attacks;
    }

    private ArrayList<WsAttack> verify(WsAttack doNotBreakAttackSeed, WsAttack breakAttackSeed, Probe probe, int chosen_escape, String mutation) {
        ArrayList<WsAttack> attacks = new ArrayList<>(2);
        WsAttack mergedBreakAttack = new WsAttack();
        mergedBreakAttack.addAttack(breakAttackSeed);
        WsAttack mergedDoNotBreakAttack = new WsAttack();
        mergedDoNotBreakAttack.addAttack(doNotBreakAttackSeed);

        WsAttack tempDoNotBreakAttack = doNotBreakAttackSeed;

        int confirmations = BulkUtilities.globalSettings.getInt("confirmations");
        boolean boostedConfirmations = false;
        for (int i=0; i<confirmations; i++) {
            WsAttack tempBreakAttack = buildAttackFromProbe(probe, probe.getNextBreak(), mutation);
            mergedBreakAttack.addAttack(tempBreakAttack);

            if (WsBulkUtilities.similar(mergedDoNotBreakAttack, tempBreakAttack) || (probe.getRequireConsistentEvidence() && WsBulkUtilities.similarIsh(mergedDoNotBreakAttack, mergedBreakAttack, tempDoNotBreakAttack, tempBreakAttack))) {
                return new ArrayList<>();
            }

            if (boostedConfirmations && mergedDoNotBreakAttack.size() > mergedBreakAttack.size()+5) {
                continue;
            }

            tempDoNotBreakAttack = buildAttackFromProbe(probe, probe.getNextEscapeSet()[chosen_escape], mutation);
            mergedDoNotBreakAttack.addAttack(tempDoNotBreakAttack);

            if (WsBulkUtilities.similar(mergedBreakAttack, tempDoNotBreakAttack) || (probe.getRequireConsistentEvidence() && WsBulkUtilities.similarIsh(mergedDoNotBreakAttack, mergedBreakAttack, tempDoNotBreakAttack, tempBreakAttack))) {
                return new ArrayList<>();
            }

            if (i == confirmations-1 && !boostedConfirmations) {
                HashSet<String> keys = WsAttack.getNonMatchingPrints(mergedDoNotBreakAttack, mergedBreakAttack);
                if (tempBreakAttack.allKeysAreQuantitative(keys)) {
                    confirmations = BulkUtilities.globalSettings.getInt("quantitative confirmations");
                    boostedConfirmations = true;
                }
            }

        }

        tempDoNotBreakAttack = buildAttackFromProbe(probe, probe.getNextEscapeSet()[chosen_escape], mutation);
        mergedDoNotBreakAttack.addAttack(tempDoNotBreakAttack);
        WsAttack tempBreakAttack = buildAttackFromProbe(probe, probe.getNextBreak(), mutation);
        mergedBreakAttack.addAttack(tempBreakAttack);

        if (WsBulkUtilities.similarIsh(mergedDoNotBreakAttack, mergedBreakAttack, tempDoNotBreakAttack, tempBreakAttack) || (probe.getRequireConsistentEvidence() && WsBulkUtilities.similar(mergedBreakAttack, tempDoNotBreakAttack))) {
            return new ArrayList<>();
        }

        if (!boostedConfirmations) {
            HashSet<String> keys = WsAttack.getNonMatchingPrints(mergedDoNotBreakAttack, mergedBreakAttack);
            if (tempBreakAttack.allKeysAreQuantitative(keys)) {
                return new ArrayList<>();
            }
        }

        attacks.add(mergedBreakAttack);
        attacks.add(mergedDoNotBreakAttack);

        return attacks;
    }

    private WsAttack buildAttackFromProbe(Probe probe, String payload, String mutation) {
        boolean randomAnchor = probe.getRandomAnchor();
        byte prefix = probe.getPrefix();

        String anchor = "";
        if (randomAnchor) {
            anchor = BulkUtilities.generateCanary();
        }

        String base_payload = payload;
        String base_message = base.payload().toString();
        int startI = base_message.indexOf("FU");
        int endI = base_message.indexOf("ZZ");
        String baseValue = base_message.substring(startI + 2, endI);
        
        // i did implement this using regex first, however somehow it broke the fuzzing
        // this logic might appear slight different from the original, but it does the same
        // but since i could call or write a buldRequest method, this does something similar
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
        WebSocketMessageImpl req = new WebSocketMessageImpl(ByteArray.byteArray(payload), base.direction(), base.upgradeRequest(), base.annotations(), BulkUtilities.globalSettings.getInt("ws: timeout"));

        return new WsAttack(req, probe, base_payload, anchor);
    }

    WsAttack buildAttack(String payload, boolean random) {
        String canary = "";
        ByteArray fPayload;

        String baseMessageString = base.payload().toString();
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

        WebSocketMessageImpl request = new WebSocketMessageImpl(fPayload, base.direction(), base.upgradeRequest(), base.annotations(), BulkUtilities.globalSettings.getInt("ws: timeout"));

        return new WsAttack(request);
    }

}
