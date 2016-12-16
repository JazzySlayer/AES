package com.company;

/**
 * Created by Sushant on 10/31/2016.
 */
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class TestFinal {
    private static final String ALGORITHM = "AES";
    private static final String CIPHER_GETINSTANCE = "AES/CBC/PKCS5Padding";
    private static final BASE64Encoder ENCODER_64 = new BASE64Encoder();
    private static final BASE64Decoder DECODER_64 = new BASE64Decoder();
    private static final String ENCRYPTION_KEY = "tvIJgJdjAyVmSQuZKGLFh0M4cAF4VDQrWVag0fLBv+o=";
    static byte[] ivSpec1 = new byte[]
            {
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            };
    private static Cipher CIPHER_ENCODER;
    private static Cipher CIPHER_DECODER;
    private static synchronized Cipher getCipherInstance(boolean encoder)
            throws NoSuchAlgorithmException, NoSuchPaddingException,
            IOException, InvalidKeyException,
            InvalidAlgorithmParameterException {
        synchronized (ALGORITHM) {
            if (CIPHER_ENCODER == null
                    || CIPHER_DECODER == null) {
                CIPHER_ENCODER = Cipher
                        .getInstance(CIPHER_GETINSTANCE);
                CIPHER_DECODER = Cipher
                        .getInstance(CIPHER_GETINSTANCE);
                byte[] keyBytes = new byte[32];
                BASE64Decoder d64 = new BASE64Decoder();
                byte[] b = d64.decodeBuffer(ENCRYPTION_KEY);
                int len = b.length;
                if (len > keyBytes.length) {
                    len = keyBytes.length;
                }
                System.arraycopy(b, 0, keyBytes, 0, len);
                SecretKeySpec keySpec = new SecretKeySpec(keyBytes, ALGORITHM);
                IvParameterSpec ivSpec = new IvParameterSpec(ivSpec1);
                CIPHER_ENCODER.init(Cipher.ENCRYPT_MODE, keySpec,
                        ivSpec);
                CIPHER_DECODER.init(Cipher.DECRYPT_MODE, keySpec,
                        ivSpec);
                System.out.println("Here is key ....>"+keySpec);
            }
        }
        if (encoder) {
            return CIPHER_ENCODER;
        } else {
            return CIPHER_DECODER;
        }
    }
    public static String encrypt(final String msg) throws IOException,
            NoSuchAlgorithmException, GeneralSecurityException {
        String encryptedMsg = "";
        byte[] encrypt = getCipherInstance(true).doFinal(msg.getBytes("UTF-8"));
        encryptedMsg = ENCODER_64.encode(encrypt);
        return encryptedMsg;
    }
    public static void main(String[] arg) {
        try {
            String en = encrypt(arg[0]);
            System.out.println(en);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
