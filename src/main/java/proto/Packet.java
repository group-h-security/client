package proto;

// okay so knowing how packets are send using TCP i have a general idea about how this should look
// each packet should have a magic header, this ensures that we are actually sending a valid packet,
// just like how an executable file like MachO has a 4 (i think) byte magic number at the top, denoting
// that it is indeed a MachO executable file

// so along with this each packet represents an action, some of which should absolutely include
// we can denote the following with one byte, so header then opcode
// HEARTBEAT: ensure user is alive -> 0x01
// CREATE_ROOM: create a room, give back roomCode -> 0x02
// JOIN_ROOM: given a room code, join that room -> 0x03
// CHAT_SEND: obvious -> 0x04
// LEAVE: obvious -> 0x05
// HEARTBEAT_ACK: acknowledge the server -> 0x01

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

// ill put these in an interface called Op
public class Packet {
    public static final int MAGIC = 0x43484154; // "CHAT"
    public static final int HEADER_SIZE = 12; // header is 12 bytes

    public byte opcode; // the action of our packet
    public byte version = 1; // this is a good idea if protocol changes

    // ordered list of TLV's that make up payload
    public final List<Tlv> tlvs = new ArrayList<>();

    // encoding, we should be able to serialise a packet into a byte array ready to write to a socket
    public byte[] toBytes() {
        // for each tlv, calc size, adds all lengths up
        int payloadLen = tlvs.stream().mapToInt(Tlv::size).sum();

        // because bytebuffers are easy to deal with
        ByteBuffer buf = ByteBuffer.allocate(HEADER_SIZE + payloadLen).order(ByteOrder.BIG_ENDIAN);

        // now to create our packet we put header, version, opcode, and payload length
        buf.putInt(MAGIC);         // CHAT
        buf.put(version);          // 1
        buf.put(opcode);           // anything in Op
        buf.putShort((short)0);    // reserved, alignment, was told this is good idea
        buf.putInt(payloadLen);    // payload length in bytes

        // now write tlvs to ByteBuffer
        for (Tlv t : tlvs) {
            t.writeTo(buf);
        }

        // then return as byte[]
        return buf.array();
    }

    // decoding, should return a nice Packet class
    public static Packet read(InputStream inputStream) throws IOException {
        // read header into byte array
        byte[] header = readFully(inputStream, HEADER_SIZE);
        if (header == null) return null; // this is a problem

        // allows is to play with header easier
        ByteBuffer hb = ByteBuffer.wrap(header).order(ByteOrder.BIG_ENDIAN);

        // grab magic
        int magic = hb.getInt(); // read 4 bytes, position now 4

        if(magic != MAGIC) {
            throw new IOException("bad magic :(");
        }

        byte ver =  hb.get(); // read 1 byte, position now 5
        byte op =  hb.get(); // read 1 byte, position now 6
        hb.getShort(); // reserved but consume
        int payloadLen = hb.getInt();

        // not good, or good, could be typing packet or something
        if (payloadLen < 0) {
            throw new IOException("negative payload length");
        }

        // read payload
        byte[] payload = readFully(inputStream, payloadLen);
        if (payload == null) {
            throw new EOFException("unexpected EOF in payload");
        }

        Packet pkt = new Packet();
        pkt.version = ver;
        pkt.opcode  = op;
        // parse tlvs
        ByteBuffer pb = ByteBuffer.wrap(payload).order(ByteOrder.BIG_ENDIAN);

        while (pb.hasRemaining()) { // read till end
            if (pb.remaining() < 4) { // tlv header being 4 bytes
                throw new IOException("truncated tlv header");
            }
            int type = Short.toUnsignedInt(pb.getShort()); // grab type
            int len  = Short.toUnsignedInt(pb.getShort()); // length of content
            if (len > pb.remaining()) {
                throw new IOException("tlv length longer than remaining, not good bro");
            }
            byte[] value = new byte[len]; // value of said tlv
            pb.get(value); // put in byte buffer
            pkt.tlvs.add(new Tlv(type, value)); // add tlv to packet
        }

        // yes man got packet
        return pkt;
    }

    private static byte[] readFully(InputStream inputStream, int n) throws IOException {
        // create new byte array, length of n to store bytes read from in
        byte[] b = new byte[n];
        // how many bytes have been read so far
        int off = 0;
        // continue reading till n, meaning we have read n bytes
        while (off < n) {
            // read bytes into b, off to n-off
            int r = inputStream.read(b, off, n - off);

            // if r is -1, this means we reached the end of the stream before reading n bytes
            // if no bytes are read at all, off == 0, just return null
            // anyways just return b containing only bytes successfully read
            if (r == -1) return off == 0 ? null : Arrays.copyOf(b, off);

            // add number of bytes just read to off
            off += r;
        }

        // successfully read n bytes
        return b;
    }

    // add tlv to packet
    public Packet addStr(int type, String s) {
        tlvs.add(Tlv.ofStr(type, s));
        return this;
    }

    // add u32 to packet
    public Packet addU32(int type, long v) {
        tlvs.add(Tlv.ofU32(type, v));
        return this;
    }

    // add u64 to packet
    public Packet addU64(int type, long v) {
        tlvs.add(Tlv.ofU64(type, v));
        return this;
    }

    // add byte array to packet
    public Packet addBytes(int type, byte[] v) {
        tlvs.add(new Tlv(type, v));
        return this;
    }

    public String getStr(int type) {
        for (Tlv t : tlvs) if (t.type == type) return t.asStr();
        return null;
    }

    public Long getU32(int type) {
        for (Tlv t : tlvs) if (t.type == type) return t.asU32();
        return null;
    }

    public Long getU64(int type) {
        for (Tlv t : tlvs) if (t.type == type) return t.asU64();
        return null;
    }

    // TLV subclass
    public static final class Tlv {
        // this should be a short, 16 bit unsigned
        public final int type; // the actual field id, eg USERNAME=0x0001
        public final byte[] value; // the value of the field, we can interpret this how we want, String, int whatever

        public Tlv(int type, byte[] value) {
            this.type = type;
            this.value = value;
        }

        // number of bytes the Tlv will occupy
        public int size() {
            return 2 + 2 + value.length; // each tlv header is 4 bytes + the value length
        }

        // okay so ByteBuffers have more convinient methods to deal with byte arrays
        public void writeTo(ByteBuffer b) {
            b.putShort((short) type);
            b.putShort((short) value.length);
            b.put(value);
        }

        // okay so we dont want to encode everything as strings, we have usernames messages room codes
        // these can be interpreted differently, like u32 could store content length of the actual message
        // u64 could store a timestamp, note sure if we actually need this but we are here now

        // utf-8 encoded because standards are good and we love emojis
        public static Tlv ofStr(int type, String s) { // given string
            byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
            return new Tlv(type, bytes);
        }

        // 4byte tlv stored as BIG_ENDIAN because thats apparently a standard
        public static Tlv ofU32(int type, long v) { // we need lower 4 bytes
            ByteBuffer b = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN);
            b.putInt((int) v);
            return new Tlv(type, b.array());
        }

        // same for 8byte
        public static Tlv ofU64(int type, long v) { // we need lower 8 bytes
            ByteBuffer b = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN);
            b.putLong(v);
            return new Tlv(type, b.array());
        }

        // interpret tlv as str
        public String asStr() {
            return new String(value, StandardCharsets.UTF_8);
        }

        // THANKS GPT SOMETHING GOT TO DO WITH JAVA BEING WEIRD ABOUT SMALL NUMBERS
        // interpret as u32
        public long asU32() {
            if (value.length != 4) throw new IllegalStateException("U32 requires 4 bytes");
            return ByteBuffer.wrap(value).order(ByteOrder.BIG_ENDIAN).getInt() & 0xFFFF_FFFFL;
        }

        // interpret as u64
        public long asU64() {
            if (value.length != 8) throw new IllegalStateException("U64 requires 8 bytes");
            return ByteBuffer.wrap(value).order(ByteOrder.BIG_ENDIAN).getLong();
        }

    }

}




