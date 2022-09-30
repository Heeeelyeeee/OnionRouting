import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Node class makes a node that connects to the directory node.
 * This allows it to be picked by a client and then proceeds to make a safe tunnel to let the client send http request to a given server.
 */
public class Node {
    final static String PC = "127.0.0.1";
    static String splitRegex = "<!!!>";
    static String portRegex = "x!x!";
    static String secretKeyRegex = "!thisIsAesKeyMessage!";
    static String iVRegex = "!thisIsAesIV!";
    static int currentPort;
    static int toPort;
    static String pcTo;
    static private InputStream reciverInputstream;
    static private EncryptionTools nodeEncryptionTools = new EncryptionTools();
    static private Socket ReciverSocket;
    static private byte[] whatToSendBack;
    static private boolean firstMessage = true;
    static private PrivateKey rsaPrivateKey;
    static private PublicKey rsaPublicKey;

    /**
     * Makes a pair of RSA keys
     * @throws NoSuchAlgorithmException
     */
    private static void RSAKeyPairGenerator() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(4096);
        KeyPair pair = keyGen.generateKeyPair();
        rsaPrivateKey = pair.getPrivate();
        rsaPublicKey = pair.getPublic(); //send to client
    }

    /**
     * Decrypts a RSA message
     * @param rsaMessage
     * @return
     * @throws InvalidKeyException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    private static byte[] decyperRSAmessage(byte[] rsaMessage) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException {
        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
        return decryptCipher.doFinal(rsaMessage);
    }

    /**
     * Makes a AES key from a given message with the public key
     * @param aesmessage
     */
    private static void makeAesFromAesMessage(byte[] aesmessage){

        byte[] key = split(secretKeyRegex.getBytes(StandardCharsets.UTF_8),split(iVRegex.getBytes(StandardCharsets.UTF_8), aesmessage).get(0)).get(1);
        nodeEncryptionTools.initFromStrings(Base64.getEncoder().encodeToString(key));
    }

    /**
     * Decrypts a message using a AES public key, and the IV wich is written in plane text in front of the messages.
     * @param encrypted
     * @return
     * @throws Exception
     */
    private static byte[] decriptAESmessage(byte[] encrypted) throws Exception {
        return nodeEncryptionTools.decrypt(encrypted);
    }

    /**
     * Encrypts a messsage with AES. Adds IV in plane text in front of message.
     * @param decypted
     * @return
     * @throws Exception
     */
    private static byte[] encryptWithAes(byte[] decypted) throws Exception {
        return nodeEncryptionTools.encrypt(decypted);
    }

    /**
     * Takes in a multiple of byte[] and makes them into one bug byte[]. This methode is used when adding Splitting regex to messages.
     * @param arrays
     * @return resulting byte[]
     */
    public static byte[] concat(byte[]... arrays)
    {
        // Determine the length of the result array
        int totalLength = 0;
        for (int i = 0; i < arrays.length; i++)
        {
            if(arrays[i] != null){
                totalLength += arrays[i].length;
            }

        }

        // create the result array
        byte[] result = new byte[totalLength];

        // copy the source arrays into the result array
        int currentIndex = 0;
        for (int i = 0; i < arrays.length; i++)
        {
            if(arrays[i] != null){
                System.arraycopy(arrays[i], 0, result, currentIndex, arrays[i].length);
                currentIndex += arrays[i].length;
            }

        }

        return result;
    }

    /**
     * Methode to check if a byte[] contains a pattern. if so it returns true.
     * @param pattern
     * @param input
     * @param pos
     * @return
     */
    public static boolean isMatch(byte[] pattern, byte[] input, int pos) {
        for(int i=0; i< pattern.length; i++) {
            if(pattern[i] != input[pos+i]) {
                return false;
            }
        }
        return true;
    }

    /**
     * Methode to check if a byte[] contains a pattern. if so it returns true.
     * @param pattern
     * @param input
     * @return
     */
    public static boolean isMatch(byte[] pattern, byte[] input) {
        for(int i=0; i<input.length; i++){
            if(isMatch(pattern,input,i)){
                return true;
            }
        }
        return false;
    }

    /**
     * Helper split methode used on byte[] to get diffrent parts of an byte[].
     * @param pattern
     * @param input
     * @return
     */
    public static List<byte[]> split(byte[] pattern, byte[] input) {
        List<byte[]> l = new LinkedList<byte[]>();
        int blockStart = 0;
        for(int i=0; i<input.length; i++) {
            if(isMatch(pattern,input,i)) {
                l.add(Arrays.copyOfRange(input, blockStart, i));
                blockStart = i+pattern.length;
                i = blockStart;
            }
        }
        l.add(Arrays.copyOfRange(input, blockStart, input.length ));
        return l;
    }


    //Methode to add the node into the SpringBoot server which contains info about all the nodes

    /**
     * Methode that adds this node to the directory node
     * @throws IOException
     */
    public static void addMeToDirectoryNode() throws IOException {
        URL url = new URL("http://localhost:8080/?PORTNR=" + PC + portRegex + currentPort );
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();

        //request setup
        connection.setRequestMethod("POST");
        connection.getResponseCode();

    }

    /**
     * methode that sends the public key of this node to the directory node
     * @throws IOException
     */
    public static void sendPublicKey() throws IOException {
        URL url = new URL("http://localhost:8080/publicKey/");
        HttpURLConnection con = (HttpURLConnection) url.openConnection();

        con.setRequestMethod("PUT");
        con.setDoOutput(true);
        con.getOutputStream().write(rsaPublicKey.getEncoded());
        con.getResponseMessage();
    }

    /**
     * Delete the public key from the directory node.
     * @throws IOException
     */
    public static void DeletePublicKey() throws IOException {
        URL url = new URL("http://localhost:8080/Delete/publicKey/");
        HttpURLConnection con = (HttpURLConnection) url.openConnection();

        con.setRequestMethod("PUT");
        con.setDoOutput(true);
        con.getOutputStream().write(rsaPublicKey.getEncoded());
        con.getResponseMessage();
    }
    //Methode that returns a String of all the nodes that are added into the directoryNode (SpringBoot Server)

    /**
     * Gets all nodes that are available in the directory node
     * @return
     * @throws IOException
     */
    public static String getNodes() throws IOException {
        URL url = new URL("http://localhost:8080/");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();

        //request setup
        connection.setRequestMethod("GET");
        connection.setConnectTimeout(5000);
        connection.setReadTimeout(5000);

        connection.getResponseCode();
        String line = "";
        String nodes = "";

        BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        while((line = reader.readLine())!=null){
            nodes += line;
        }
        return nodes;
    }

    //Methode that removes the node from the directory node (Springboot server)

    /**
     * Remove itself from directoryNode
     * @throws IOException
     */
    public static void removeMeFromDirectoryNode() throws IOException {
        URL url = new URL("http://localhost:8080/DELETE/?PORTNR=" + PC + "x!x!" + currentPort);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();

        //request setup
        connection.setRequestMethod("POST");
        connection.getResponseCode();
        DeletePublicKey();
    }

    //Gets the entire message from a input stream and returns it
    /**
     * Gets all bytes in a inputstream and sets them together to a byte[].
     * @param inputstream
     * @return
     * @throws IOException
     */
    public static byte[] getMessageFromInputStream(InputStream inputstream ) throws IOException {
        ByteArrayOutputStream bytearray = new ByteArrayOutputStream();

        byte[] buffer = new byte[1024];
        int bytesRead;
        while (inputstream.available() > 0 && (bytesRead = inputstream.read(buffer, 0, buffer.length)) > 0) {
            bytearray.write(buffer, 0, bytesRead);
        }
        return bytearray.toByteArray();
    }

    public static void main(String[] args) throws Exception {

            //Get all current running nodes
            String nodesAllready = getNodes();
            int max = 8060;
            int min = 8001;

            do {//Genreates a port on this pc where a new node can run
                currentPort = (int) Math.floor(Math.random() * (max - min + 1) + min);
            } while (nodesAllready.contains(PC + "x!x!" + currentPort));
            RSAKeyPairGenerator();



            // Starts running on a localPort
            ServerSocket senderToNode = new ServerSocket(currentPort);
            addMeToDirectoryNode();
            sendPublicKey();

            Socket senderConnection = senderToNode.accept();
            //made connection so it should not be accessible for other clients at that moment
            removeMeFromDirectoryNode();

            InputStream nodeBeforeMeInputStream = senderConnection.getInputStream();

            //check for AES keys
            byte[] posibleKey = getMessageFromInputStream(nodeBeforeMeInputStream);

            posibleKey = decyperRSAmessage(posibleKey);
            makeAesFromAesMessage(posibleKey);
            byte[] gotTheAesMesaage = encryptWithAes("Got AES".getBytes(StandardCharsets.UTF_8));
            senderConnection.getOutputStream().write(gotTheAesMesaage);


            //Loops to check if more message are sendt from the sender
            System.out.println("Ready :)");
            while(true) {

                //Wait for initial message
                while (nodeBeforeMeInputStream.available() == 0) { }
                //Get message from nodeBeforeMeInputStream:

                byte[] message = decriptAESmessage(getMessageFromInputStream(nodeBeforeMeInputStream));
                while(nodeBeforeMeInputStream.available()>0){
                    message = concat(message,getMessageFromInputStream((nodeBeforeMeInputStream)));
                    TimeUnit.MILLISECONDS.sleep(200);
                }

                List<byte[]> splittedMessage = split(splitRegex.getBytes(StandardCharsets.UTF_8),message);

                //Checks if the message is being sent to another node or if it is a HTTP request:

                if (isMatch(portRegex.getBytes(StandardCharsets.UTF_8), message) && firstMessage) {//Send the message to another node
                    firstMessage = false;
                    toPort = Integer.parseInt(new String(split(portRegex.getBytes(StandardCharsets.UTF_8),splittedMessage.get(0)).get(1)));
                    pcTo = new String(split(portRegex.getBytes(StandardCharsets.UTF_8),splittedMessage.get(0)).get(0));

                    //makes new message
                    message = Arrays.copyOfRange(message,splittedMessage.get(0).length + splitRegex.getBytes(StandardCharsets.UTF_8).length,message.length);   /*message.substring(splittedMessage[0].length() + "<!!!>".length());*/
                    ReciverSocket = new Socket(pcTo, toPort);

                    reciverInputstream = ReciverSocket.getInputStream();

                    ReciverSocket.getOutputStream().write(message);

                    //Wait for respons from the node infront
                    boolean gotMessage = false;

                    while (!gotMessage) {
                        if (!(reciverInputstream == null) && reciverInputstream.available() > 0) {
                            //Handling PACKET

                            byte[] respons = getMessageFromInputStream(reciverInputstream);
                            whatToSendBack = concat(whatToSendBack, respons);

                            TimeUnit.MILLISECONDS.sleep(200);
                            if(reciverInputstream.available() ==0){
                                gotMessage = true;
                            }
                        }

                    }

                }else if(isMatch(portRegex.getBytes(StandardCharsets.UTF_8), message)&& !firstMessage){
                    message = Arrays.copyOfRange(message,splittedMessage.get(0).length + splitRegex.getBytes(StandardCharsets.UTF_8).length,message.length); ;

                    ReciverSocket.getOutputStream().write(message);

                    //Wait for respons from the node infront
                    boolean gotMessage = false;

                    while (!gotMessage) {
                        if (!(reciverInputstream == null) && reciverInputstream.available() > 0) {
                            //Handling PACKET

                            byte[] respons = getMessageFromInputStream(reciverInputstream);
                            whatToSendBack = concat(whatToSendBack, respons);

                            TimeUnit.MILLISECONDS.sleep(200);
                            if(reciverInputstream.available() ==0){
                                gotMessage = true;
                            }
                        }

                    }

                }
                else {
                    toPort = 80;

                    String myAttempt = new String(split("\r\n".getBytes(StandardCharsets.UTF_8),split("Host: ".getBytes(StandardCharsets.UTF_8),message).get(1)).get(0));
                    InetAddress[] myAttemptIpList = InetAddress.getAllByName(myAttempt);

                    InetAddress myAttemptIp  = myAttemptIpList[0];

                    ReciverSocket = new Socket(myAttemptIp, toPort);

                    reciverInputstream = ReciverSocket.getInputStream();


                    ReciverSocket.getOutputStream().write(message);

                    boolean recivedRequest = false;
                    while (!recivedRequest) {
                        if (!(reciverInputstream == null) && reciverInputstream.available() > 0) {
                            byte[] respons = getMessageFromInputStream(reciverInputstream);
                            whatToSendBack = concat(whatToSendBack, respons);
                            TimeUnit.MILLISECONDS.sleep(200);
                            if(reciverInputstream.available() ==0){
                                recivedRequest = true;
                            }

                        }
                    }

                }
                //sends respons
                whatToSendBack = nodeEncryptionTools.encrypt(whatToSendBack);
                senderConnection.getOutputStream().write(whatToSendBack);
                //reset value
                whatToSendBack = "".getBytes(StandardCharsets.UTF_8);


            }

        }

}
