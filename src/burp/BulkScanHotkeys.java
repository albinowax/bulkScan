package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.hotkey.HotKey;
import burp.api.montoya.ui.hotkey.HotKeyContext;
import burp.api.montoya.ui.hotkey.HotKeyEvent;

import java.util.ArrayList;
import java.util.List;

public class BulkScanHotkeys {

    private static final HotKeyContext[] CONTEXTS = {
            HotKeyContext.HTTP_MESSAGE_EDITOR,
            HotKeyContext.PROXY_HTTP_HISTORY,
            HotKeyContext.INTRUDER_ATTACK_RESULTS,
            HotKeyContext.ORGANIZER_ENTRIES,
            HotKeyContext.SITE_MAP_CONTENTS_TABLE
    };

    private static final String[][] KEY_PATTERNS = {
            // Pattern 1: Ctrl+Alt+Shift+F1-F12
            {"Ctrl+Alt+Shift+F1", "Ctrl+Alt+Shift+F2", "Ctrl+Alt+Shift+F3", "Ctrl+Alt+Shift+F4",
             "Ctrl+Alt+Shift+F5", "Ctrl+Alt+Shift+F6", "Ctrl+Alt+Shift+F7", "Ctrl+Alt+Shift+F8",
             "Ctrl+Alt+Shift+F9", "Ctrl+Alt+Shift+F10", "Ctrl+Alt+Shift+F11", "Ctrl+Alt+Shift+F12"},
            // Pattern 2: Ctrl+Shift+F1-F12
            {"Ctrl+Shift+F1", "Ctrl+Shift+F2", "Ctrl+Shift+F3", "Ctrl+Shift+F4",
             "Ctrl+Shift+F5", "Ctrl+Shift+F6", "Ctrl+Shift+F7", "Ctrl+Shift+F8",
             "Ctrl+Shift+F9", "Ctrl+Shift+F10", "Ctrl+Shift+F11", "Ctrl+Shift+F12"},
            // Pattern 3: Alt+Shift+F1-F12
            {"Alt+Shift+F1", "Alt+Shift+F2", "Alt+Shift+F3", "Alt+Shift+F4",
             "Alt+Shift+F5", "Alt+Shift+F6", "Alt+Shift+F7", "Alt+Shift+F8",
             "Alt+Shift+F9", "Alt+Shift+F10", "Alt+Shift+F11", "Alt+Shift+F12"}
    };

    private int currentKeyIndex = 0;

    public void register(MontoyaApi api, List<Scan> scans, String extensionName) {
        for (Scan scan : scans) {
            String hotKeyName = extensionName + ": " + scan.name;
            String keyBinding = allocateNextKey();

            if (keyBinding == null) {
                BulkUtilities.err("Failed to register hotkey for " + scan.name + ": all key combinations exhausted");
                continue;
            }

            boolean registered = tryRegisterForAllContexts(api, scan, hotKeyName, keyBinding);

            // If registration failed, try fallback keys
            while (!registered && currentKeyIndex < getTotalKeys()) {
                keyBinding = allocateNextKey();
                if (keyBinding == null) {
                    BulkUtilities.err("Failed to register hotkey for " + scan.name + ": all key combinations exhausted");
                    break;
                }
                registered = tryRegisterForAllContexts(api, scan, hotKeyName, keyBinding);
            }

            if (registered) {
                BulkUtilities.out("Registered hotkey '" + hotKeyName + "' with binding: " + keyBinding);
            }
        }
    }

    private boolean tryRegisterForAllContexts(MontoyaApi api, Scan scan, String hotKeyName, String keyBinding) {
        try {
            for (HotKeyContext context : CONTEXTS) {
                api.userInterface().registerHotKeyHandler(
                        context,
                        HotKey.hotKey(hotKeyName, keyBinding),
                        event -> handleHotKey(event, scan, context)
                );
            }
            return true;
        } catch (Exception e) {
            // Key binding collision - try next key
            return false;
        }
    }

    private void handleHotKey(HotKeyEvent event, Scan scan, HotKeyContext context) {
        List<HttpRequestResponse> selected;

        if (context == HotKeyContext.HTTP_MESSAGE_EDITOR) {
            if (event.messageEditorRequestResponse().isEmpty()) {
                return;
            }
            selected = List.of(event.messageEditorRequestResponse().get().requestResponse());
        } else {
            selected = event.selectedRequestResponses();
        }

        if (selected.isEmpty()) {
            return;
        }

        // Convert to IHttpRequestResponse array using shared converter
        IHttpRequestResponse[] reqs = selected.stream()
                .map(BulkScanContextMenu::convertToIHttpRequestResponse)
                .toArray(IHttpRequestResponse[]::new);

        TriggerBulkScan.launchScan(scan, reqs);
    }

    private String allocateNextKey() {
        if (currentKeyIndex >= getTotalKeys()) {
            return null;
        }
        int patternIndex = currentKeyIndex / 12;
        int keyIndex = currentKeyIndex % 12;
        currentKeyIndex++;
        return KEY_PATTERNS[patternIndex][keyIndex];
    }

    private int getTotalKeys() {
        return KEY_PATTERNS.length * 12; // 36 total
    }
}
