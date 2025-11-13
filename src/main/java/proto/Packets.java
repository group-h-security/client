package proto;

import grouph.core.DataManager;
import grouph.core.Room;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.UUID;

// small helper for building Packet instances
// can be used on client and server
public final class Packets {
    // nice
    private Packets() {}

    // we are alive
    public static Packet heartbeat() {
        Packet p = new Packet();
        p.opcode = Op.HEARTBEAT;
        return p;
    }

    // for client to send
    public static Packet createRoom() {
        Packet p = new Packet();
        p.opcode = Op.CREATE_ROOM;
        return p;
    }

    // for client to send
    public static Packet joinRoom(String roomCode) {
        Packet p = new Packet();
        p.opcode = Op.JOIN_ROOM;
        return p.addStr(T.ROOM_CODE, roomCode);
    }

    // for client to send
    public static Packet chatSend(String message) {
        byte[] bytes = message.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        Packet p = new Packet();
        p.opcode = Op.CHAT_SEND;
        return p.addU32(T.CONTENT_LEN, bytes.length)
            .addStr(T.MESSAGE, message);
    }

    // for client to send
    public static Packet leave() {
        Packet p = new Packet();
        p.opcode = Op.LEAVE;
        return p;
    }

    public static Packet setUsername(String username) {
        Packet p = new Packet();
        p.opcode = Op.SET_USERNAME;
        return p.addStr(T.USERNAME, username);
    }

    public static Packet getLogs() {
        Packet p = new Packet();
        p.opcode = Op.GET_LOGS;
        return p;
    }

    // for server to send

    public static Packet getLogsAck(String chatLogs) {
        Packet p = new Packet();
        p.opcode = Op.GET_LOGS_ACK;
        return p.addStr(T.CHAT_LOGS, chatLogs);
    }

    public static Packet heartbeatAck(long nowMs) {
        Packet p = new Packet();
        p.opcode = Op.HEARTBEAT_ACK;
        return p.addU64(T.TIMESTAMPMS, nowMs);
    }

    // for server to send
    public static Packet createRoomAck(UUID roomId, String roomCode) {
        Packet p = new Packet();
        p.opcode = Op.CREATE_ROOM_ACK;
        return p.addBytes(T.ROOM_ID, uuidToBytes(roomId))
            .addStr(T.ROOM_CODE, roomCode);
    }

    public static Packet setUsernameAck(String username) {
        Packet p = new Packet();
        p.opcode = Op.SET_USERNAME_ACK;
        return p.addStr(T.USERNAME, username);
    }

    // for server to send
    public static Packet joinRoomAck(UUID roomId, String roomCode) {
        Packet p = new Packet();
        p.opcode = Op.JOIN_ROOM_ACK;
        return p.addBytes(T.ROOM_ID, uuidToBytes(roomId))
            .addStr(T.ROOM_CODE, roomCode);
    }

    // for server to send
    public static Packet chatBroadcast(String username, String message) {
        byte[] bytes = message.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        Packet p = new Packet();
        p.opcode = Op.CHAT_BROADCAST;
        return p.addStr(T.USERNAME, username)
            .addU32(T.CONTENT_LEN, bytes.length)
            .addStr(T.MESSAGE, message);
    }

    // for server to send
    public static Packet userJoined(String username) {
        Packet p = new Packet();
        p.opcode = Op.USER_JOINED;
        return p.addStr(T.USERNAME, username);
    }

    // for server to send
    public static Packet userLeft(String username) {
        Packet p = new Packet();
        p.opcode = Op.USER_LEFT;
        return p.addStr(T.USERNAME, username);
    }

    // for server to send
    public static Packet error(int code, String reason) {
        Packet p = new Packet();
        p.opcode = Op.ERROR;
        return p.addU32(T.ERROR_CODE, code)
            .addStr(T.REASON, reason);
    }

    // write packet to socket
    public static void write(OutputStream out, Packet pkt) throws IOException {
        out.write(pkt.toBytes());
        out.flush();
    }

    // read packet from socket
    public static Packet read(InputStream in) throws IOException {
        return Packet.read(in);
    }

    // validate CHAT_SEND length is actually correct
    public static boolean validateContentLen(Packet pkt) {
        String msg = pkt.getStr(T.MESSAGE);
        Long declared = pkt.getU32(T.CONTENT_LEN);
        if (msg == null || declared == null) return false;
        int actual = msg.getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
        return declared == actual;
    }


    // UUID encode
    public static byte[] uuidToBytes(UUID id) {
        ByteBuffer b = ByteBuffer.allocate(16).order(ByteOrder.BIG_ENDIAN);
        b.putLong(id.getMostSignificantBits()).putLong(id.getLeastSignificantBits());
        return b.array();
    }

    // decode
    public static UUID bytesToUuid(byte[] bytes) {
        if (bytes == null || bytes.length != 16) throw new IllegalArgumentException("UUID needs 16 bytes");
        ByteBuffer b = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN);
        long msb = b.getLong();
        long lsb = b.getLong();
        return new UUID(msb, lsb);
    }

}
