package com.the008.app.cryptoutil;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

/**
 * AES (Advanced Encryption Standard) 256-bits using CBC/PKCS5Padding compatible with OpenSSL
 * @author Victor Lima de Andrade <victor.the008@gmail.com>
 * @since 2016-06-25
 * @version 1.0
 */
public abstract class AESOpenSSLKeyUtil {

    public static final int AES_KEY_SIZE = 32; /* 256 bits */
    public static final String AES_MECHANISM = "AES/CBC/PKCS5Padding";
    public static final String HASH_MECHANISM = "MD5";
    public static final String SECURE_RANDOM_MECHANISM = "SHA1PRNG";
    public static final int IV_SIZE = 16; /* 128 bits */
    public static final int SALT_SIZE = 8; /* 64 bits */
    public static final int BUFFER_SIZE = 1024;
    public static final byte[] AES_OPENSSL_HEADER = "Salted__".getBytes();

    public static String generatePassword() {
        try {
            SecureRandom sr = SecureRandom.getInstance(SECURE_RANDOM_MECHANISM);
            byte[] pwd = new byte[AES_KEY_SIZE];
            sr.nextBytes(pwd);
            return Base64.encodeBase64String(pwd);
        } catch (Exception e) {
            throw new RuntimeException("Error generating password: " + e.getMessage(), e);
        }
    }

    public static void encryptNoSalt(InputStream input, String password, OutputStream output) {
        encrypt(input, password, output, false);
    }
    
    public static void encrypt(InputStream input, String password, OutputStream output) {
        encrypt(input, password, output, true);
    }
    
    private static void encrypt(InputStream input, String password, OutputStream output, boolean useSalt) {
        byte[] salt = null;
        if(useSalt){
            salt = generateSalt();
        }
        byte[][] keys = generateAesKeyIVOpenSSL(salt, password.getBytes());
        byte[] key = keys[0];
        byte[] iv = keys[1];

        Cipher cipher;
        try{
            cipher = Cipher.getInstance(AES_MECHANISM);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        }catch(GeneralSecurityException e){
            throw new RuntimeException("Error loading encryption mechanism: "+e.getMessage(), e);
        }

        try{
            if(useSalt){
                output.write(AES_OPENSSL_HEADER);
                output.write(salt);
            }
    
            byte[] buffer = new byte[BUFFER_SIZE];
            int numRead;
            byte[] encrypted = null;
            while ((numRead = input.read(buffer)) > 0) {
                encrypted = cipher.update(buffer, 0, numRead);
                if (encrypted != null) {
                    output.write(encrypted);
                }
            }
            try {
                encrypted = cipher.doFinal();
            } catch (IllegalBlockSizeException | BadPaddingException impossible) {
            }
            if (encrypted != null) {
                output.write(encrypted);
            }
        }catch(IOException e){
            throw new RuntimeException("Error processing encryption: "+e.getMessage(), e);
        }
    }

    public static void decrypt(InputStream input, String password, OutputStream output){
        byte[] salted = new byte[SALT_SIZE];
        byte[] salt = new byte[SALT_SIZE];
        byte[][] keys;
        try{
            input.read(salted); /* Read AES OpenSSL Header */
            input.read(salt);
            if(Arrays.equals(salted, AES_OPENSSL_HEADER)){
                keys = generateAesKeyIVOpenSSL(salt, password.getBytes());
            }else{
                input.reset();
                keys = generateAesKeyIVOpenSSL(null, password.getBytes());
            }
        }catch(IOException e){
            throw new RuntimeException("Error reading encrypted message: "+e.getMessage(), e);
        }
        
        byte[] key = keys[0];
        byte[] iv = keys[1];

        Cipher cipher;
        try{
            cipher = Cipher.getInstance(AES_MECHANISM);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        }catch(GeneralSecurityException e){
            throw new RuntimeException("Error loading decryption mechanism: "+e.getMessage(), e);
        }

        byte[] buffer = new byte[BUFFER_SIZE];
        int numRead;
        byte[] decrypted = null;
        try{
            while ((numRead = input.read(buffer)) > 0) {
                decrypted = cipher.update(buffer, 0, numRead);
                if (decrypted != null) {
                    output.write(decrypted);
                }
            }
            try {
                decrypted = cipher.doFinal();
            } catch (IllegalBlockSizeException | BadPaddingException e) {
                throw new RuntimeException("Error processing decryption: "+e.getMessage(), e);
            }
            if (decrypted != null) {
                output.write(decrypted);
            }
        }catch(IOException e){
            throw new RuntimeException("Error processing decryption: "+e.getMessage(), e);
        }
    }

    private static byte[] generateSalt() {
        SecureRandom sr;
        try {
            sr = SecureRandom.getInstance(SECURE_RANDOM_MECHANISM);
        } catch (Exception e) {
            throw new RuntimeException("Error loading secure random mechanism: " + e.getMessage(), e);
        }
        byte[] salt = new byte[SALT_SIZE];
        sr.nextBytes(salt);
        return salt;
    }

    public static byte[][] generateAesKeyIVOpenSSL(byte[] salt, byte[] data) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance(HASH_MECHANISM);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error loading hashing mechanism: " + e.getMessage(), e);
        }
        int count = 1;
        byte[][] both = new byte[2][];
        byte[] key = new byte[AES_KEY_SIZE];
        int key_ix = 0;
        byte[] iv = new byte[IV_SIZE];
        int iv_ix = 0;
        both[0] = key;
        both[1] = iv;
        byte[] md_buf = null;
        int nkey = AES_KEY_SIZE;
        int niv = IV_SIZE;
        int i = 0;
        if (data == null) {
            return both;
        }
        int addmd = 0;
        for (;;) {
            md.reset();
            if (addmd++ > 0) {
                md.update(md_buf);
            }
            md.update(data);
            if (null != salt) {
                md.update(salt, 0, 8);
            }
            md_buf = md.digest();
            for (i = 1; i < count; i++) {
                md.reset();
                md.update(md_buf);
                md_buf = md.digest();
            }
            i = 0;
            if (nkey > 0) {
                for (;;) {
                    if (nkey == 0)
                        break;
                    if (i == md_buf.length)
                        break;
                    key[key_ix++] = md_buf[i];
                    nkey--;
                    i++;
                }
            }
            if (niv > 0 && i != md_buf.length) {
                for (;;) {
                    if (niv == 0)
                        break;
                    if (i == md_buf.length)
                        break;
                    iv[iv_ix++] = md_buf[i];
                    niv--;
                    i++;
                }
            }
            if (nkey == 0 && niv == 0) {
                break;
            }
        }
        for (i = 0; i < md_buf.length; i++) {
            md_buf[i] = 0;
        }
        return both;
    }

}
