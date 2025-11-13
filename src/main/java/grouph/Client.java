package grouph;

import java.nio.file.Path;
import java.util.Scanner;
import java.security.KeyStore;
import java.nio.file.Files;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;


import proto.Packet;//importing Ryan's Packet library to communicate with the server
import proto.Packets;
import proto.Op;
import proto.T;

public class Client {

    clientCertificateManager clientCertificateManager = new clientCertificateManager();//make certificate handlr obj to access its behaviours
    private String Username = "Anythhing";// just a placeholder for the running script
    private String RoomCode = "000000";// placeholder var
    private static final String pass;   

    static {
        try {
            pass = Files.readString(Path.of("stores/keystorePass.txt"), StandardCharsets.UTF_8).trim();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    private static final String CLIENT_KEYSTORE = "stores/client-truststore.jks";
    private static final String CLIENT_TRUSTSTORE = "stores/client-truststore.jks";

    private SSLSocket socket;
    private static InputStream in;//stream for reading server reply
    private static OutputStream out;//stream for sending user 

    private static final String HOST = "localhost";//just building with local host
    private static final int PORT = 8443;

    public void start() {
        try {
            //call cert handler start to write a csr
            clientCertificateManager.start();

            //make the client socket
            socket = createClientSocket();
            in = socket.getInputStream();
            out = socket.getOutputStream();

            //force handshake
            socket.startHandshake();
            SSLSession sesh = socket.getSession();
            if (sesh.isValid()) throw new Exception("SSL session failed to init");//test to see if all went as anticipated

            //ask the end-user to enter a username and send the corresponding packet to the server
            getUsername();

            //Prompt for room command or chat messages
            commandLoop();

        } catch (Exception e) {
            System.out.println("Error encountered, please see Error message attached: " + e.getMessage());
        } finally {
            closeConnection();
        }
    }

    private void commandLoop() throws Exception {
        Scanner inp = new Scanner(System.in);

        while (true) {
            System.out.print("Please etner a command: ");
            String command = inp.nextLine().trim();

            if (command.startsWith("/createRoom")) {
                Packet createPakt = Packets.createRoom();
                Packets.write(out, createPakt);

            } else if (command.startsWith("/joinRoom")) {
                String roomNum = command.substring(10);//skip /joinroom
                Packet joinPakt = Packets.joinRoom(roomNum);
                Packets.write(out, joinPakt);

                } else if (command.startsWith("/help")) {
                    System.out.printf("");

                System.out.println(Username +": " +message);

                //nested while so they can leave the room and do something else
                    boolean inChat = true;
                    while (inChat) {
                        String msg = inp.nextLine().trim();
                        if (msg.equals("/leave")) {
                            Packet leavePkt = Packets.leave();
                            Packets.write(out, leavePkt);
                            inChat = false; //leave inner loop
                        } else if (msg.startsWith("/message ")) {
                            Packet chatPkt = Packets.chatSend(msg.substring(9));//skip /messgae
                            Packets.write(out, chatPkt);
                        }
                    }

                    } else {
                        System.out.println("Unknown command., Please try again");
                    }

                    inp.close();
                }
            }

            private void getUsername() throws Exception {
                Scanner inp = new Scanner(System.in);
                System.out.print("Enter Username: ");
                Username = inp.nextLine().trim();

                Packet setName = Packets.setUsername(Username);
                Packets.write(out, setName);

                System.out.println("Username set: " + Username);
                inp.close();;
            }

                private void listenAndWait() {//method to wait for server repsonse to prevent blocking
                
                }

                private void closeConnection(){

                }

                    private void determineServerPacket(Packet pakt) {
        
                            if(pakt.opcode == Op.CHAT_BROADCAST){
                                    System.out.println("[" + pakt.getStr(T.USERNAME) + "]: " + pakt.getStr(T.MESSAGE));
                            } else if (pakt.opcode == Op.USER_JOINED ){
                                System.out.println(pakt.getStr(T.USERNAME) + " joined the room");
                            } else if (pakt.opcode == Op.USER_LEFT){
                                 System.out.println(pakt.getStr(T.USERNAME) + " left the room");
                            } else if (pakt.opcode == Op.SET_USERNAME_ACK){
                                System.out.println("Username confirmed by server: " + pakt.getStr(T.USERNAME));
                            } else if (pakt.opcode == Op.CREATE_ROOM_ACK){
                                System.out.println("Room created: " + pakt.getStr(T.ROOM_CODE));
                            } else if (pakt.opcode == Op.JOIN_ROOM_ACK){
                                System.out.println("Joined room: " + pakt.getStr(T.ROOM_CODE));
                            } else if (pakt.opcode == Op.HEARTBEAT_ACK){
                                //need to ping to let server know im still connected i believe
                            } else {
                                System.out.println("Unkown packet received from server" +pakt.opcode);
                            }

                    }

                private SSLSocket createClientSocket() throws Exception {
                      
                KeyStore ks = KeyStore.getInstance("JKS");
                    try (FileInputStream fis = new FileInputStream(CLIENT_KEYSTORE)) {
                        ks.load(fis, pass.toCharArray());
                    }

                // create keymanager
                KeyManagerFactory kmf = KeyManagerFactory.getInstance(
                    KeyManagerFactory.getDefaultAlgorithm()
                );
                kmf.init(ks, pass.toCharArray());

            // load client truststore
            KeyStore ts = KeyStore.getInstance("JKS");
            try (FileInputStream fis = new FileInputStream(CLIENT_TRUSTSTORE)) {
                ts.load(fis, pass.toCharArray());
            }

            // checke server cert
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm()
            );
            tmf.init(ts);


            // create SSLContext
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

        // create SSLSocket
        SSLSocketFactory factory = sslContext.getSocketFactory();
        SSLSocket sock = (SSLSocket) factory.createSocket(HOST, PORT);//on the correct host and port

        return sock;                  
        
    }

}