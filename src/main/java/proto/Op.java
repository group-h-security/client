package proto;

public interface Op {
    // lets define every single type of packet the server can handle
    // client -> server
    byte HEARTBEAT = 0x01;
    byte CREATE_ROOM = 0x02;
    byte JOIN_ROOM = 0x03;
    byte CHAT_SEND = 0x04;
    byte LEAVE = 0x05;
    byte SET_USERNAME = 0x06;
    byte GET_LOGS = 0x07;

    // server -> client
    byte HEARTBEAT_ACK = 0x11;
    byte CREATE_ROOM_ACK = 0x12;
    byte JOIN_ROOM_ACK = 0x13;
    byte CHAT_BROADCAST = 0x14;
    byte USER_JOINED = 0x15;
    byte USER_LEFT = 0x16;
    byte LEAVE_ACK = 0x17;
    byte SET_USERNAME_ACK = 0x18;
    byte GET_LOGS_ACK = 0x19;

    // error
    byte ERROR = 0x7F;

    // new
}
