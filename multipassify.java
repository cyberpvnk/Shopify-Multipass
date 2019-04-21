package com.acme.sso;

import org.json.JSONObject;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.ssl.OpenSSL;

import java.nio.charset.StandardCharsets;
import java.security.CryptoPrimitive;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
//import java.util.Date;
import java.time.LocalDateTime;
import java.net.URLEncoder;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SsoExample3
{
    private static String API_KEY = "qwertyuiopasdfghjklzxcvbnm123456";
    private static int BLOCK_SIZE = 16;
    private static String DOMAIN = "yourSauce.myshopify.com";


    public static void main(String[] args)
    {
        try {

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(API_KEY.getBytes(StandardCharsets.UTF_8));
            byte[] encryptionKeyDigest = Arrays.copyOfRange(digest, 0, BLOCK_SIZE);
            byte[] signatureKeyDigest= Arrays.copyOfRange(digest, BLOCK_SIZE, 2*BLOCK_SIZE);

            SecretKeySpec encryptionKey = new SecretKeySpec(encryptionKeyDigest, "AES");
            SecretKeySpec signatureKey = new SecretKeySpec(signatureKeyDigest, "AES");

            // DATA ***
            String zonedDT = ZonedDateTime.now(ZoneOffset.UTC ).format(DateTimeFormatter.ISO_INSTANT );
            String data = "{ \"email\": \"test@example.com\", \"created_at\": \"" +  zonedDT  +"\" }";

            // Initialization vector
            SecureRandom random = new SecureRandom();
            byte[] iv = new byte[BLOCK_SIZE];
            random.nextBytes(iv);                             // <-- UNCOMMENT this
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            // Javax Encryption
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, ivSpec);
            byte[] firstBit = cipher.update(data.getBytes(StandardCharsets.UTF_8));
            byte[] lastBit = cipher.doFinal();
            byte[] javaxEncryptedData = new byte[iv.length + firstBit.length + lastBit.length];
            System.arraycopy(iv, 0,
                             javaxEncryptedData, 0,
                             iv.length);
            System.arraycopy(firstBit, 0,
                             javaxEncryptedData, iv.length,
                             firstBit.length);
            System.arraycopy(lastBit, 0,
                             javaxEncryptedData, iv.length + firstBit.length,
                             lastBit.length);

            // Sign the data
            Mac sha256HMAC  = Mac.getInstance("HmacSHA256");
            sha256HMAC.init(signatureKey);
            byte[] signedJavaxEncryptedData = sha256HMAC.doFinal(javaxEncryptedData);


            byte[] combinedJavaxEnccryptedData =
                    new byte[javaxEncryptedData.length + signedJavaxEncryptedData.length];
            System.arraycopy(javaxEncryptedData, 0,
                             combinedJavaxEnccryptedData, 0,
                             javaxEncryptedData.length);
            System.arraycopy(signedJavaxEncryptedData, 0,
                             combinedJavaxEnccryptedData, javaxEncryptedData.length,
                             signedJavaxEncryptedData.length);
            String javaxEncryptedBase64EncodedToken =
                    Base64.encodeBase64URLSafeString(combinedJavaxEnccryptedData);

            System.out.println( "https://" + DOMAIN + "/account/login/multipass/" + javaxEncryptedBase64EncodedToken );

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}