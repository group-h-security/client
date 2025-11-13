package proto;

// this allows us to reorder fields like username, roomcode, message
// packet might have header, including magic, with an opcode, then the first field might be username
// which we would denote with a T of maybe 0x0001
// i believe this is known as TLV, an encoding scheme https://en.wikipedia.org/wiki/Type%E2%80%93length%E2%80%93value
public interface T {
    int USERNAME = 0x0001; // str
    int ROOM_CODE = 0x0002; // str
    int ROOM_ID = 0x0003; // 16 bytes
    int MESSAGE = 0x0004; // str
    int CONTENT_LEN = 0x0005; // u32
    int REASON = 0x0006; // str
    int TIMESTAMPMS = 0x0007; // u64
    int ERROR_CODE = 0x0008; // u32
    int CHAT_LOGS = 0x0009; // str
}
