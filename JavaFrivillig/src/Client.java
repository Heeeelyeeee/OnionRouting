import javax.crypto.*;
import java.awt.*;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * The Client class is a class which lets a user use a directory node and other nodes to setup a secure tunnel, which it then can make http request from. This class ensures anonymity and encryption of data.
 * The client class requires 3 nodes to be running, and a directory node.
 */
public class Client {

    static String PC;
    static int PORTNR;
    static String nodes;
    static byte[] res;
    static String splitRegex = "<!!!>";
    static String portRegex = "x!x!";
    static List<byte[]>rsaPublicKeys = new ArrayList<>();
    static List<byte[]> aesKeysMessages = new ArrayList<>();
    static String secretKeyRegex = "!thisIsAesKeyMessage!";
    static ArrayList<Cipher> RsaCipersForNodes = new ArrayList<>();
    static ArrayList<EncryptionTools> aesforNodes = new ArrayList<>();

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
     * Makes a AES key and stores it in a ArrayList of AES keys. also Stores the public key in another Array so it can easly be sent to other nodes.
     * @throws Exception
     */
    public static void makeAESkey() throws Exception {
        EncryptionTools encryptionTools = new EncryptionTools();
        encryptionTools.init();

        aesforNodes.add(encryptionTools);
        aesKeysMessages.add(concat(secretKeyRegex.getBytes(StandardCharsets.UTF_8), encryptionTools.getKey()));
    }

    /**
     * AES encrypts a byte[] with a given AES which is stored in a array. The interger param is to define which AES that the message should be encrypted with.
     * @param decrypted
     * @param i
     * @return
     * @throws Exception
     */
    public static byte[] aesEncryption(byte[] decrypted, int i) throws Exception {
        return aesforNodes.get(i).encrypt(decrypted);
    }

    /**
     * Get a given public key from the directoryNode with a HTTP get request.
     * @param i
     * @throws IOException
     * @throws InterruptedException
     */
    public static void getPublicKeys(int i) throws IOException, InterruptedException {
        URL url = new URL("http://localhost:8080/getPublicKeys/?HvilkenPB=" + i);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();

        //request setup
        connection.setRequestMethod("GET");
        connection.setConnectTimeout(5000);
        connection.setReadTimeout(5000);
        connection.getResponseCode();
        TimeUnit.MILLISECONDS.sleep(500);
        rsaPublicKeys.add(Base64.getDecoder().decode(getMessageFromInputStream(connection.getInputStream())));

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

    /**
     * Gets all node IPs and port numbers by sending a http GET request to the directory node.
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


        while(true) {
            //gets all nodes
            nodes = getNodes();

            //Total ndoes which are going to be visited
            int nodesVisted = 3;
            ArrayList<Integer> nodeNumbers = new ArrayList<>();

            for (int i = 0; i < nodesVisted; i++) {
                nodeNumbers.add(i);
            }
            //makes the path random
            Collections.shuffle(nodeNumbers);



            //Makes RSA keys from info that it gets from directory node
            for(int i = 0; i<nodesVisted; i++){
                getPublicKeys(nodeNumbers.get(i));
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(rsaPublicKeys.get(i));
                Cipher encryptCipher = Cipher.getInstance("RSA");

                encryptCipher.init(Cipher.ENCRYPT_MODE, keyFactory.generatePublic(publicKeySpec));
                RsaCipersForNodes.add(encryptCipher);
            }

            //makes aes keys for all nodes
            for(int i = 0; i<nodesVisted; i++){
                makeAESkey();
            }

            //Port which the next node is on
            PORTNR = Integer.parseInt(nodes.split(splitRegex)[nodeNumbers.get(0)].split(portRegex)[1]);
            //IP for the next node
            PC = nodes.split(splitRegex)[nodeNumbers.get(0)].split(portRegex)[0];


            //Make pathway that will be appended to the messages
            byte[] pathwayN2 = (nodes.split(splitRegex)[nodeNumbers.get(1)] + splitRegex).getBytes(StandardCharsets.UTF_8);
            byte[] pathwayN3 = (nodes.split(splitRegex)[nodeNumbers.get(2)] + splitRegex).getBytes(StandardCharsets.UTF_8);

            //Makes socket connection with node that will receive all messages.
            Socket connection = new Socket(PC, PORTNR);
            InputStream responsInputStream = connection.getInputStream();
            Scanner sc = new Scanner(System.in);


            //send all aes keys to respective nodes.
            byte[] message1 = aesKeysMessages.get(0);
            message1 = RsaCipersForNodes.get(0).doFinal(message1);
            connection.getOutputStream().write(message1);
            TimeUnit.MILLISECONDS.sleep(800);
            byte[] responsFromFirst = getMessageFromInputStream((connection.getInputStream()));
            while(connection.getInputStream().available()>0){
                responsFromFirst = concat(responsFromFirst,getMessageFromInputStream((connection.getInputStream())));
                TimeUnit.MILLISECONDS.sleep(100);
            }

            byte[] message2 = aesKeysMessages.get(1);
            message2 = aesEncryption(concat(nodes.split(splitRegex)[nodeNumbers.get(1)].getBytes(StandardCharsets.UTF_8),splitRegex.getBytes(StandardCharsets.UTF_8),RsaCipersForNodes.get(1).doFinal(message2)),0);
            connection.getOutputStream().write(message2);
            TimeUnit.MILLISECONDS.sleep(500);
            byte[] responsFromSecond = getMessageFromInputStream((connection.getInputStream()));
            while(connection.getInputStream().available()>0){
                responsFromSecond = concat(responsFromSecond,getMessageFromInputStream((connection.getInputStream())));
                TimeUnit.MILLISECONDS.sleep(100);
            }

            byte[] message3 = aesKeysMessages.get(2);
            message3 = aesEncryption(concat(nodes.split(splitRegex)[nodeNumbers.get(1)].getBytes(StandardCharsets.UTF_8),splitRegex.getBytes(StandardCharsets.UTF_8),aesEncryption(concat(nodes.split(splitRegex)[nodeNumbers.get(2)].getBytes(StandardCharsets.UTF_8),splitRegex.getBytes(StandardCharsets.UTF_8),RsaCipersForNodes.get(2).doFinal(message3)),1)),0);
            connection.getOutputStream().write(message3);
            TimeUnit.MILLISECONDS.sleep(500);
            byte[] responsFromThird = getMessageFromInputStream((connection.getInputStream()));
            TimeUnit.MILLISECONDS.sleep(500);
            while(connection.getInputStream().available()>0){
                responsFromThird = concat(responsFromThird,getMessageFromInputStream((connection.getInputStream())));
                TimeUnit.MILLISECONDS.sleep(100);
            }
            //end of sending AES keys

            while(true) {
                res = null;

                //lets the user start by entring newline
                System.out.println("PRESS ENTER TO SEND HTTP REQUEST");
                String start = sc.nextLine();

                //hardcoded http request. didnt find a better way to let the user make http request without setting up a proxy server.
                byte[] message;
                //this message was for testing if the program could handle a repsos of 4.2mb, IT DID :D. ATM it converts it into html,
                // so it wont be so impressive, but at the end of the program you can make the resulting file a txt file so you can se the entire respons :D

                //message = "GET /flasgger_static/swagger-ui-bundle.js HTTP/1.1\r\nHost: httpbin.org\r\nCache-Control: max-age=0\r\n\r\n";
                message = "GET / HTTP/1.1\r\nHost: datakom.no\r\nCache-Control: max-age=0\r\n\r\n".getBytes(StandardCharsets.UTF_8);

                //Makes onioned message with all aes encription
                byte[] Onionedmessage = aesEncryption(concat(pathwayN2,aesEncryption(concat(pathwayN3,aesEncryption(message,2)),1)),0);
                connection.getOutputStream().write(Onionedmessage);
                System.out.println("Sent message:");
                System.out.println(new String(Onionedmessage));


                boolean messageBack = false;

                while (!messageBack) {
                    if (responsInputStream.available() > 0) {

                        byte[] respons = getMessageFromInputStream(responsInputStream);
                        res = concat(res,respons);
                        TimeUnit.MILLISECONDS.sleep(200);
                        if(responsInputStream.available() ==0){
                            messageBack = true;
                        }


                    }
                }// end of while waiting for response
                //res = aesDecryption(aesDecryption(aesDecryption(res,nodeNumbers.get(2)),nodeNumbers.get(1)),nodeNumbers.get(0));
                byte[] DecryoptFirst = aesforNodes.get(0).decrypt(res);
                byte[] DecryoptSecond = aesforNodes.get(1).decrypt(DecryoptFirst);;
                byte[] DecryoptThird = aesforNodes.get(2).decrypt(DecryoptSecond);;

                File file = new File("test.html");

                BufferedWriter writeToFile = new BufferedWriter(new FileWriter(file.getName()));
                writeToFile.write(new String(DecryoptThird));
                writeToFile.close();

                Desktop.getDesktop().browse(file.toURI());

            }//main loop for sending and receiving messages

        }
    }

}