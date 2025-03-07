package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.contextmenu.WebSocketMessage;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.websocket.Direction;
import burp.api.montoya.websocket.BinaryMessage;
import burp.api.montoya.websocket.TextMessage;
import burp.api.montoya.websocket.extension.ExtensionWebSocketCreation;
import burp.api.montoya.websocket.extension.ExtensionWebSocketCreationStatus;
import burp.api.montoya.websocket.extension.ExtensionWebSocketMessageHandler;

import static burp.Scan.throttle;

import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class WebSocketMessageImpl implements WebSocketMessage {
    private final ByteArray payload;
    private final Direction direction;
    private final HttpRequest upgradeRequest;
    private final Annotations annotations;

    private final List<ByteArray> responses;
    private final List<Long> responseTimes;
    private final List<MessageType> responseTypes;
    private final long timeout; // window of time to

    public enum MessageType {
        TEXT, BINARY
    }

    private IResponseVariations attributes;

    @Override
    public ByteArray payload() {
        return payload;
    }

    @Override 
    public Direction direction() {
        return direction;
    }

    @Override 
    public HttpRequest upgradeRequest() {
        return upgradeRequest;
    }

    @Override
    public Annotations annotations() {
        return annotations;
    }

    public List<ByteArray> responses() {
        return responses;
    }

    public List<Long> responseTimes() {
        return responseTimes;
    }

    public long responseTime() {
        if (responseTimes.isEmpty()) {
            return Long.MAX_VALUE;
        }
        return Collections.min(responseTimes);
    }

    public List<MessageType> responseTypes() {
        return responseTypes;
    }

    IResponseVariations getAttributes() {
        if (attributes == null) {
            byte[][] byteResponses = responses.stream()
                                     .map(ByteArray::getBytes)
                                     .toArray(byte[][]::new);
            attributes = Utilities.helpers.analyzeResponseVariations(byteResponses);
        }
        return attributes;
    }

    long getAttribute(String attribute) {
        switch(attribute) {
            case "time":
                return responseTimes.isEmpty() ? Long.MAX_VALUE : Collections.min(responseTimes);
            case "failed":
                return responses.isEmpty() ? 1 : 0;
            case "timedout":
                return responses.isEmpty() ? 1 : 0;
        }

        try {
            return getAttributes().getAttributeValue(attribute, 0);
        } catch (IllegalArgumentException e) {
            Utilities.out("Invalid attribute: "+attribute);
            Utilities.out("Supported attributes: "+getAttributes().getInvariantAttributes() + getAttributes().getVariantAttributes());
            throw new RuntimeException("Invalid attribute: "+attribute);
        }

    }

    public WebSocketMessageImpl(ByteArray payload, Direction direction, HttpRequest upgradeRequest, Annotations annotations, long timeout) {
        this.payload = payload;
        this.direction = direction;
        this.upgradeRequest = upgradeRequest;
        this.annotations = annotations;
        this.timeout = timeout;

        this.responses = new ArrayList<>();
        this.responseTimes = new ArrayList<>();
        this.responseTypes = new ArrayList<>();

        wsRequest(upgradeRequest, payload);
    }

    private void wsRequest(HttpRequest upgradeRequest, ByteArray payload_tmp) {
        final MontoyaApi api = Utilities.montoyaApi;

        ByteArray payload;
        // remove FUZZ placeholder in case it's still here, can happen sometimes
        Pattern pattern = Pattern.compile("FU(.*?)ZZ");
        Matcher matcher = pattern.matcher(payload_tmp.toString());
        if (matcher.find()) {
            String payload_s = matcher.replaceAll("$1");
            payload = ByteArray.byteArray(payload_s);
        } else {
            payload = payload_tmp;
        }

        throttle();

        try {
            ExtensionWebSocketCreation webSocketCreation = api.websockets().createWebSocket(upgradeRequest);
        
            if (webSocketCreation.status() != ExtensionWebSocketCreationStatus.SUCCESS) {
                Utilities.out("WebSocket creation failed: " + webSocketCreation.status());
                Utilities.out(upgradeRequest.toString());
                return;
            }

            webSocketCreation.webSocket().ifPresent(extensionWebSocket -> {
                long startTime = System.nanoTime();

                extensionWebSocket.registerMessageHandler(new ExtensionWebSocketMessageHandler() {
                    @Override
                    public void textMessageReceived(TextMessage message) {
                        synchronized (responses) {
                            responseTimes.add(System.nanoTime() - startTime);
                            responses.add(ByteArray.byteArray(message.payload()));
                            responseTypes.add(MessageType.TEXT);
                        }
                    }

                    @Override
                    public void binaryMessageReceived(BinaryMessage message) {
                        synchronized (responses) {
                            responseTimes.add(System.nanoTime() - startTime);
                            responses.add(message.payload());
                            responseTypes.add(MessageType.BINARY);
                        }
                    }
                });

                // messages to be sent before the payloads (e.g. auth)
                String preMessage = Utilities.globalSettings.getString("ws: pre-message");

                if (!preMessage.isEmpty()) {
                    String[] preMessages = preMessage.split("FUZZ");
                    for (String value : preMessages) {
                        extensionWebSocket.sendTextMessage(value);
                    }
                }

                extensionWebSocket.sendBinaryMessage(payload);

                try {
                    Thread.sleep(timeout * 1000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    extensionWebSocket.close();
                }
            });

        } catch (Exception e) {
            Utilities.out("WebSocket request failed: " + e.getMessage());
        }
    }

}
