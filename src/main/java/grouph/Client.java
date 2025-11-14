package grouph;

import proto.Op;
import proto.Packet;
import proto.Packets;
import proto.T;

import javax.net.ssl.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.NoSuchElementException;
import java.util.Scanner;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

public class Client {
    private final CertificateManager certificateManager = new CertificateManager(); // grab certs
    private SSLSocket socket; // socket we are communicating with
    private OutputStream out; // to write packets to
    private volatile boolean connected = false; // are we connected?
    private final ConcurrentHashMap<Byte, CompletableFuture<Packet>> pending =
        new ConcurrentHashMap<>(); // packets we are waiting for a ACK from

    private void receivePacketAsync() {
        new Thread(() -> {
            try {
                while (connected) { // while client is connected
                    Packet p = Packets.read(socket.getInputStream()); // read incoming packet
                    if (p == null) break; // socket closed or no more data
                    CompletableFuture<Packet> fut = pending.remove(p.opcode); // look for matching waiter
                    if (fut != null) fut.complete(p); // complete the waiting future
                }
            } catch (Exception e) {
                // ignore exceptions in background listener
            }
        }, "packet-receiver").start();
    }

    Packet sendAndWait(Packet req, byte expect, long timeoutMs) throws Exception {
        Packets.write(out, req);                        // send request packet
        long deadline = System.currentTimeMillis() + timeoutMs; // compute timeout
        while (true) {
            Packet p = Packets.read(socket.getInputStream());    // read next packet
            if (p == null) throw new IOException("socket closed"); // no packet means socket closed
            if (p.opcode == expect) return p;                     // return if opcode matches expected
            // ignore other packets
            if (System.currentTimeMillis() > deadline)           // check timeout
                throw new IOException("timeout waiting for response");
        }
    }

    public void start() {
        try {
            certificateManager.start(); // generate csr/ts/ks and what not

            try {
                initConnection(); // start mTLS
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

            handleUserInput(); // start prompt
        } catch (Exception exc) {
            System.out.println("oh no: " + exc); // fuck
            exc.printStackTrace();
        } finally {
            cleanup();
        }
    }

    // self-explanatory
    private void handleUserInput() {
        Scanner scanner = new Scanner(System.in);
        connected = true;
        printHelp();
        while (connected) {
            System.out.print("> "); // out prompt
            String input;
            try {
                input = scanner.nextLine(); // get input
            } catch (NoSuchElementException | IllegalStateException e) {
                // some console err, sometimes idea does this had to change build.gradle
                System.out.println("\ninput unavailable");
                break;
            }
            if (input == null) break; // no input
            input = input.trim();
            if (input.isEmpty()) continue;

            try {
                if (input.startsWith("/")) { // got command
                    handleCommand(input); // handle it
                } else {
                    sendChatMessage(input); // anything else thats not a command is a message
                }
            } catch (Exception e) {
                System.out.println("err: " + e.getMessage()); // fuck
            }
        }
        connected = false;
    }

    private void handleCommand(String input) throws Exception {
        String[] parts = input.split("\\s+", 2); // split that stuff
        String command = parts[0].toLowerCase(); // /cReAtE
        String arg = parts.length > 1 ? parts[1] : null; // may be an arg

        switch (command) {
            case "/create":
                createRoom(); // done
                break;
            case "/join":
                if (arg == null) {
                    System.out.println("usage: /join <room_code>");
                } else {
                    joinRoom(arg);
                }
                break;
            case "/leave":
                leaveRoom();
                break;
            case "/username":
                if (arg == null) {
                    System.out.println("usage: /username <new_name>");
                } else {
                    setUsername(arg);
                }
                break;
            case "/help":
                printHelp();
                break;
            case "/exit":
            case "/quit":
                System.out.println("bye");
                connected = false;
                break;
            default:
                System.out.println("unknown command, please /help");
        }
    }

    private void createRoom() {
        try {
            Packet req = Packets.createRoom(); // create room packet
            Packet ack = sendAndWait(req, Op.CREATE_ROOM_ACK, 5000); // wait with a timeout of 5 sec
            if (ack != null) { // if we recieved a response
                String code = ack.getStr(T.ROOM_CODE); // we grab the room code
                System.out.println("room created, code: " + code);
                // tell the user they can allow others to join and themselves
                System.out.println("share this code to let others join");
            }
        } catch (Exception e) {
            System.out.println("failed to create room: " + e.getMessage()); // oh no
        }
    }

    // still needs implementation
    private void joinRoom(String roomCode) { /* TODO */ }
    private void leaveRoom() { /* TODO */ }
    private void setUsername(String newName) { /* TODO */ }
    private void sendChatMessage(String text) { /* TODO */ }

    // show user availiable commands
    private void printHelp() {
        System.out.println("available commands:");
        System.out.println("/create - create new chat room");
        System.out.println("/join <room_code> - join room");
        System.out.println("/leave - leave current room");
        System.out.println("/username <new_name> - change username");
        System.out.println("/help - show help message");
        System.out.println("/exit or /quit - exit client");
    }

    // start mTLS connection
    private void initConnection() throws Exception {
        // these wore generated earlier
        final String CLIENT_KEYSTORE   = DataManager.getDataPath("certs/client-keystore.jks");
        final String CLIENT_TRUSTSTORE = DataManager.getDataPath("client-truststore.jks");
        final String PASSWORD_FILE     = DataManager.getDataPath("certs/keystorePass.txt");

        String HOST;
        String systemIp = System.getProperty("server.ip.address"); // for ryans deployed server
        if (systemIp != null && !systemIp.isEmpty()) {
            HOST = systemIp;
            System.out.printf("using server ip: %s%n", systemIp);
        } else {
            HOST = "localhost"; // localhost if we didnt set that system prop
            System.err.println("ip address system prop not found, defaulting to localhost.");
        }
        final int PORT = 8443; // standards say

        // as before
        String password;
        try (Scanner sc = new Scanner(new File(PASSWORD_FILE))) {
            if (!sc.hasNextLine()) throw new IOException("ks file is empty");
            password = sc.nextLine().trim();
        }

        KeyStore keyStore = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(CLIENT_KEYSTORE)) {
            keyStore.load(fis, password.toCharArray());
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, password.toCharArray());

        KeyStore trustStore = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(CLIENT_TRUSTSTORE)) {
            trustStore.load(fis, "changeit".toCharArray());
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

        SSLSocketFactory factory = sslContext.getSocketFactory();
        socket = (SSLSocket) factory.createSocket(HOST, PORT);
        socket.startHandshake();

        // get the output stream of the socket
        out = socket.getOutputStream();

        // listen in background for packets to be recieved
        receivePacketAsync();

        // yup
        System.out.println("mTLS connection established to " + HOST + ":" + PORT);
    }

    // close sockets on program close
    private void cleanup() {
        connected = false;
        if (socket != null) {
            try {
                socket.close();
                System.out.println("connection closed.");
            } catch (IOException e) {
                System.out.println("error closing socket: " + e.getMessage());
            }
        }
    }
}
