package xyz.kaaniche.phoenix.iam.boundaries;

import jakarta.ejb.EJB;
import jakarta.inject.Inject;
import jakarta.json.Json;
import jakarta.json.JsonException;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import jakarta.websocket.*;
import jakarta.websocket.server.ServerEndpoint;
import xyz.kaaniche.phoenix.iam.controllers.AuditLogRepository;
import xyz.kaaniche.phoenix.iam.controllers.MessageEventManager;
import xyz.kaaniche.phoenix.iam.entities.AuditLog;

import java.io.IOException;
import java.io.StringReader;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Logger;

@ServerEndpoint(value = "/pushes",encoders = {PushWebSocketEndpoint.JSONTextEncoder.class},decoders = {PushWebSocketEndpoint.JSONTextDecoder.class})
public class PushWebSocketEndpoint {
    @Inject
    private Logger log;

    @Inject
    private AuditLogRepository auditLogRepository;

    @EJB
    private MessageEventManager messageEventManager;
    private static final Set<Session> sessions = Collections.synchronizedSet(new HashSet<>());

    public static void broadcastMessage(JsonObject message){
        for(Session session: sessions){
            try {
                session.getBasicRemote().sendObject(message);
            } catch (IOException | EncodeException e) {
                throw new RuntimeException(e);
            }
        }
    }

    @OnOpen
    public void onOpen(Session session){
        log.info("Push WebSocket Opened: "+session.getId());
        auditLogRepository.save(new AuditLog("anonymous", "WEBSOCKET_OPEN", "WebSocket session opened: " + session.getId(), "websocket"));
        sessions.add(session);
    }

    @OnClose
    public void onClose(Session session, CloseReason closeReason){
        log.info("Push WebSocket closed for "+session.getId()
                +" with reason ["+closeReason.getCloseCode()+":"+closeReason.getReasonPhrase()+"]");
        auditLogRepository.save(new AuditLog("anonymous", "WEBSOCKET_CLOSE", "WebSocket session closed: " + session.getId() + ", reason: " + closeReason.getCloseCode() + ":" + closeReason.getReasonPhrase(), "websocket"));
        sessions.remove(session);
    }

    @OnError
    public void onError(Session session,Throwable throwable){
        log.warning("Push WebSocket error for "+session.getId()+": "+ throwable.getMessage());
        auditLogRepository.save(new AuditLog("anonymous", "WEBSOCKET_ERROR", "WebSocket error for session: " + session.getId() + ", error: " + throwable.getMessage(), "websocket"));
    }

    @OnMessage
    public void onMessage(JsonObject message,Session session){
        auditLogRepository.save(new AuditLog("anonymous", "WEBSOCKET_MESSAGE", "WebSocket message received for session: " + session.getId(), "websocket"));
        if(session.isOpen() && session.isSecure()) {
            messageEventManager.publishFromClient(message);
        }
    }

    static final class JSONTextEncoder implements Encoder.Text<JsonObject> {
        @Override
        public String encode(JsonObject jsonObject) throws EncodeException {
            return jsonObject.toString();
        }
    }

    static final class JSONTextDecoder implements Decoder.Text<JsonObject> {
        @Override
        public JsonObject decode(String s) throws DecodeException {
            try (JsonReader jsonReader = Json.createReader(new StringReader(s))) {
                return jsonReader.readObject();
            }
        }

        @Override
        public boolean willDecode(String s) {
            try (JsonReader jsonReader = Json.createReader(new StringReader(s))) {
                jsonReader.readObject();
                return true;
            }catch (JsonException e){
                return false;
            }
        }
    }
}
