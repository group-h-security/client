package grouph;

public class Client {

    private String Username = "Anythhing";// just a placeholder for the running script
    private String RoomCode = "000000";// placeholder var
    clientCertificateManager clientCertRequestAndStore = new clientCertificateManager();//make certificate handlr obj to access its behaviours

    public void start() {//start method to start the chain and keep the main class clean
        userPrompt();//need to see how were going to structure this
            try {
                clientCertRequestAndStore.start();//call upon the certificateHandlr start method()
                initConnection();//call upon the creation of the client socket
            } catch (Exception exc) {
                System.out.println("We ran into some issues, please see Error message: " + exc);
            }
        }

        private void userPrompt() {//placeholder until im ready to take user inp
            System.out.println("Please enter your Username: ");
            // Username = x.nextLine();
            System.out.println("Succesfully assigned username: " + Username);

            System.out.println("Please enter a six digit code");
            // RoomCode = x.nextLine();
            System.out.println("RoomCode taken: " + RoomCode);

            System.out.println("Please enter Command");
            String Command = "createRoom/joinRoom";
            // msg = x.nextLine();
            System.out.println("Command taken: " + Command);

            // need to add simple inp validation for room code and username, Letters only and 6 digit maximum code
            // x.close();
        }

    private void initConnection() {
            //sslContext
            //implement protoc
            //enforce handshake
            //userInp()                    
        
    }

}