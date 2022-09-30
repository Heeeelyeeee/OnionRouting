import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedList;
import java.util.List;

/**
 * Possible KEY_SIZE values are 128, 192 and 256
 * Possible T_LEN values are 128, 120, 112, 104 and 96
 */

public class EncryptionTools {
    private SecretKey key;
    private int KEY_SIZE = 128;
    private int T_LEN = 128;
    private byte[] IV;
    static Cipher encryptionCipher;
    static String currentIvRegex = "!ivcurrent";

    public void init() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(KEY_SIZE);
        key = generator.generateKey();
    }

    public byte[] getIV() {
        return IV;
    }

    public byte[] getKey() {
        return key.getEncoded();
    }

    public void initFromStrings(String secretKey){
        key = new SecretKeySpec(decode(secretKey),"AES");
    }

    private static boolean isMatch(byte[] pattern, byte[] input, int pos) {
        for(int i=0; i< pattern.length; i++) {
            if(pattern[i] != input[pos+i]) {
                return false;
            }
        }
        return true;
    }
    private static List<byte[]> split(byte[] pattern, byte[] input) {
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

    private static byte[] concat(byte[]... arrays)
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

    public byte[] encrypt(byte[] messageInBytes) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        encryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
        encryptionCipher.init(Cipher.ENCRYPT_MODE, key);
        IV = encryptionCipher.getIV();
        byte[] encryptedBytes = concat(getIV(),currentIvRegex.getBytes(StandardCharsets.UTF_8),encryptionCipher.doFinal(messageInBytes));
        return encryptedBytes;
    }


    public byte[] decrypt(byte[] messageInBytes) throws Exception {
        Cipher decryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] currerntIv = split(currentIvRegex.getBytes(StandardCharsets.UTF_8),messageInBytes).get(0);
        GCMParameterSpec spec = new GCMParameterSpec(T_LEN, currerntIv);
        decryptionCipher.init(Cipher.DECRYPT_MODE, key, spec);
        byte[] decryptedBytes = decryptionCipher.doFinal(split(currentIvRegex.getBytes(StandardCharsets.UTF_8),messageInBytes).get(1));
        return decryptedBytes;
    }

    public static String encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    private byte[] decode(String data) {
        return Base64.getDecoder().decode(data);
    }



}