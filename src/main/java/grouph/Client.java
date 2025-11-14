package grouph;

import proto.Op;
import proto.Packet;
import proto.Packets;
import proto.T;

import javax.net.ssl.*;
import java.io.*;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.NoSuchElementException;
import java.util.Random;
import java.util.Scanner;
import java.util.UUID;
import java.util.concurrent.*;

public class Client {

    private final CertificateManager certificateManager = new CertificateManager();
    private SSLSocket socket;
    private InputStream in;
    private OutputStream out;
    private volatile boolean connected = false;
    private volatile UUID currentRoomId = null;
    private String username;

    private final ExecutorService listenerExecutor = Executors.newSingleThreadExecutor();
    private final ConcurrentHashMap<Byte, CompletableFuture<Packet>> pendingResponses =
        new ConcurrentHashMap<>();

    public void start() {
        Random rand = new Random();
        int code = 1000 + rand.nextInt(9000);
        this.username = "anon#" + code;

        try {
            certificateManager.start();

            try {
                initConnection();
            } catch (Exception e) {
                System.err.println("initial connection failed: " + e.getMessage());

                try {
                    System.out.println("updating certs ...");
                    CertificateManager.updateCerts();
                    initConnection();
                } catch (Exception ex) {
                    System.err.println("retry after updating certs failed - " + ex.getMessage());
                    System.exit(1);
                }
            }

            handleUserInput();
        } catch (Exception exc) {
            System.out.println("oh no: " + exc);
            exc.printStackTrace();
        } finally {
            cleanup();
        }
    }

    private void initConnection() throws Exception {
        final String CLIENT_KEYSTORE = DataManager.getDataPath("certs/client-keystore.jks");
        final String CLIENT_TRUSTSTORE = DataManager.getDataPath("client-truststore.jks");
        final String PASSWORD_FILE = DataManager.getDataPath("certs/keystorePass.txt");

        String HOST;
        String systemIp = System.getProperty("server.ip.address");

        if (systemIp != null && !systemIp.isEmpty()) {
            HOST = systemIp;
            System.out.printf("using server ip: %s%n", systemIp);
        } else {
            HOST = "localhost";
            System.err.println("ip address system prop not found, defaulting to localhost.");
        }

        final int PORT = 8443;

        String password;
        try (Scanner sc = new Scanner(new File(PASSWORD_FILE))) {
            if (!sc.hasNextLine()) throw new IOException("ks file is empty");
            password = sc.nextLine().trim();
        }

        KeyStore keyStore = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(CLIENT_KEYSTORE)) {
            keyStore.load(fis, password.toCharArray());
        }

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(
            KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, password.toCharArray());

        KeyStore trustStore = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(CLIENT_TRUSTSTORE)) {
            trustStore.load(fis, "changeit".toCharArray());
        }

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
            TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

        SSLSocketFactory factory = sslContext.getSocketFactory();
        socket = (SSLSocket) factory.createSocket(HOST, PORT);

        socket.setEnabledProtocols(new String[] { "TLSv1.3" });
        socket.startHandshake();

        in = socket.getInputStream();
        out = socket.getOutputStream();
        connected = true;

        System.out.println("mTLS connection established to " + HOST + ":" + PORT);

        startMessageListener();
    }

    private void startMessageListener() {
        listenerExecutor.submit(() -> {
            try {
                while (connected && !Thread.currentThread().isInterrupted()) {
                    Packet p = Packets.read(in);
                    if (p == null) {
                        System.out.println("\n[server disconnected]");
                        connected = false;
                        break;
                    }
                    handleServerMessage(p);
                }
            } catch (IOException e) {
                if (connected) {
                    System.err.println("\n[connection lost: " + e.getMessage() + "]");
                    connected = false;
                }
            }
        });
    }

    private void handleServerMessage(Packet packet) {
        CompletableFuture<Packet> future = pendingResponses.remove(packet.opcode);

        if (future != null) {
            future.complete(packet);
            return;
        }

        switch (packet.opcode) {
            case Op.CHAT_BROADCAST -> handleChatBroadcast(packet);
            case Op.USER_JOINED -> handleUserJoined(packet);
            case Op.USER_LEFT -> handleUserLeft(packet);
            case Op.ERROR -> handleError(packet);
            default -> System.out.println("[unknown message opcode: " + packet.opcode + "]");
        }
    }

    private void handleChatBroadcast(Packet p) {
        String user = p.getStr(T.USERNAME);
        String msg = p.getStr(T.MESSAGE);

        if (!user.equals(username)) {
            System.out.println("\n[" + user + "]: " + msg);
            System.out.print("> ");
        }
    }

    private void handleUserJoined(Packet p) {
        String user = p.getStr(T.USERNAME);
        if (!user.equals(username)) {
            System.out.println("\n[" + user + " joined the room]");
            System.out.print("> ");
        }
    }

    private void handleUserLeft(Packet p) {
        String user = p.getStr(T.USERNAME);
        System.out.println("\n[" + user + " left the room]");
        System.out.print("> ");
    }

    private void handleError(Packet p) {
        long code = p.getU32(T.ERROR_CODE);
        String reason = p.getStr(T.REASON);
        System.out.println("\n[err " + code + ": " + reason + "]");
        System.out.print("> ");
    }

    private void handleUserInput() {
        Scanner scanner = new Scanner(System.in);
        connected = true;

        printHelp();

        while (connected) {
            System.out.print("> ");

            String input;
            try {
                input = scanner.nextLine();
            } catch (NoSuchElementException | IllegalStateException e) {
                System.out.println("\ninput unavailable");
                break;
            }

            if (input == null) break;

            input = input.trim();
            if (input.isEmpty()) continue;

            try {
                if (input.startsWith("/")) {
                    handleCommand(input);
                } else {
                    sendChatMessage(input);
                }
            } catch (Exception e) {
                System.out.println("err: " + e.getMessage());
            }
        }

        connected = false;
    }

    private void handleCommand(String input) throws Exception {
        String[] parts = input.split("\\s+", 2);
        String command = parts[0].toLowerCase();
        String arg = parts.length > 1 ? parts[1] : null;

        switch (command) {
            case "/create" -> createRoom();
            case "/join" -> {
                if (arg == null) {
                    System.out.println("usage: /join <room_code>");
                } else {
                    joinRoom(arg);
                }
            }
            case "/leave" -> leaveRoom();
            case "/username" -> {
                if (arg == null) {
                    System.out.println("usage: /username <new_name>");
                } else {
                    setUsername(arg);
                }
            }
            case "/help" -> printHelp();
            case "/exit", "/quit" -> {
                System.out.println("bye");
                connected = false;
            }
            default -> System.out.println("unknown command, please /help");
        }
    }

    private void createRoom() {
        try {
            Packet req = Packets.createRoom();
            Packet ack = sendAndWait(req, Op.CREATE_ROOM_ACK, 5000);

            if (ack != null) {
                byte[] idBytes = ack.getBytes(T.ROOM_ID);

                if (idBytes != null && idBytes.length == 16) {
                    currentRoomId = Packets.bytesToUuid(idBytes);
                    String code = ack.getStr(T.ROOM_CODE);

                    System.out.println("Room created: " + code);
                    System.out.println("share this code to let others join");
                }
            }
        } catch (Exception e) {
            System.out.println("failed to create room: " + e.getMessage());
        }
    }

    private void joinRoom(String roomCode) throws Exception {
        Packet req = Packets.joinRoom(roomCode).addStr(T.USERNAME, username);
        Packet ack = sendAndWait(req, Op.JOIN_ROOM_ACK, 5000);

        if (ack != null) {
            byte[] idBytes = ack.getBytes(T.ROOM_ID);

            if (idBytes != null && idBytes.length == 16) {
                currentRoomId = Packets.bytesToUuid(idBytes);
                System.out.println("joined room: " + roomCode);

//                Packet logsReq = Packets.getLogs();
//                Packet logsAck = sendAndWait(logsReq, Op.GET_LOGS_ACK, 3000);
//
//                if (logsAck != null) {
//                    String chatLogs = logsAck.getStr(T.CHAT_LOGS);
//
//                    if (chatLogs != null && !chatLogs.isEmpty()) {
//                        System.out.println("--- room history ---");
//                        System.out.print(chatLogs);
//                        System.out.println("--------------------");
//                    }
//                }
            }
        }
    }

    private void leaveRoom() throws Exception {
        if (currentRoomId == null) {
            System.out.println("not in any room");
            return;
        }

        Packet req = Packets.leave();
        sendAndWait(req, Op.USER_LEFT, 5000);

        currentRoomId = null;
        System.out.println("left room");
    }

    private void setUsername(String newName) throws Exception {
        Packet req = Packets.setUsername(newName);
        sendAndWait(req, Op.SET_USERNAME_ACK, 5000);

        username = newName;
        System.out.println("username set to " + newName);
    }

    private void sendChatMessage(String text) throws Exception {
        if (currentRoomId == null) {
            System.out.println("please join a room first");
            return;
        }

        Packet msg = Packets.chatSend(text).addStr(T.USERNAME, username);
        writePacket(msg);

        System.out.println("[" + username + "]: " + text);
    }

    private Packet sendAndWait(Packet req, byte expected, long timeoutMs) throws Exception {
        CompletableFuture<Packet> future = new CompletableFuture<>();
        pendingResponses.put(expected, future);

        writePacket(req);

        try {
            return future.get(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            pendingResponses.remove(expected);
            return null;
        } catch (Exception e) {
            pendingResponses.remove(expected);
            throw e;
        }
    }

    private void writePacket(Packet p) throws IOException {
        Packets.write(out, p);
        out.flush();
    }

    private void printHelp() {
        System.out.println("""
            commands:
            /create             - create new room
            /join <room_code>   - join room
            /leave              - leave current room
            /username <name>    - change username
            /help               - show this help
            /quit or /exit      - exit client
        """);
    }

    private void cleanup() {
        connected = false;
        listenerExecutor.shutdownNow();

        if (socket != null) {
            try {
                socket.close();
                System.out.println("connection closed");
            } catch (IOException ignored) {}
        }
    }
}
