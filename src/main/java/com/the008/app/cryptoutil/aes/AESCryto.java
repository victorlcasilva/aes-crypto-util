package com.the008.app.cryptoutil.aes;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.the008.app.cryptoutil.generator.SecureRandomGenerator;
import com.the008.app.cryptoutil.util.CryptoException;

/**
 * AES (Advanced Encryption Standard) 256-bits encryption / decryption using CBC/PKCS5Padding using OpenSSL key derivation
 * @author Victor Lima de Andrade <victor.the008@gmail.com>
 * @since 2016-06-25
 * @version 1.1
 */
public abstract class AESCryto {

    private static final String AES_MECHANISM = "AES/CBC/PKCS5Padding";
    private static final String HASH_MECHANISM = "MD5";
    private static final int SALT_SIZE = 8; /* 64 bits */
    private static final int BUFFER_SIZE = 1024;
    private static final byte[] AES_OPENSSL_HEADER = "Salted__".getBytes();

    public static void encryptNoSalt(InputStream input, String password, OutputStream output) {
        encrypt(input, password, output, false);
    }
    
    public static void encrypt(InputStream input, String password, OutputStream output) {
        encrypt(input, password, output, true);
    }
    
    private static void encrypt(InputStream input, String password, OutputStream output, boolean useSalt) {
        byte[] salt = null;
        if(useSalt){
            salt = SecureRandomGenerator.generateRandom(SALT_SIZE);
        }
        byte[][] keys = generateAesKeyIVOpenSSL(salt, password.getBytes());
        byte[] key = keys[0];
        byte[] iv = keys[1];

        Cipher cipher;
        try{
            cipher = Cipher.getInstance(AES_MECHANISM);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        }catch(GeneralSecurityException e){
            throw new CryptoException("Error loading encryption mechanism: "+e.getMessage(), e);
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
            throw new CryptoException("Error processing encryption: "+e.getMessage(), e);
        }
    }

    public static void decrypt(InputStream input, String password, OutputStream output){
        byte[] salted = new byte[SALT_SIZE];
        byte[] salt = new byte[SALT_SIZE];
        byte[][] keys;
        try{
            input.read(salted); /* Read AES OpenSSL Header */
            if(Arrays.equals(salted, AES_OPENSSL_HEADER)){
                input.read(salt);
                keys = generateAesKeyIVOpenSSL(salt, password.getBytes());
            }else{
                input.reset();
                keys = generateAesKeyIVOpenSSL(null, password.getBytes());
            }
        }catch(IOException e){
            throw new CryptoException("Error reading encrypted message: "+e.getMessage(), e);
        }
        
        byte[] key = keys[0];
        byte[] iv = keys[1];

        Cipher cipher;
        try{
            cipher = Cipher.getInstance(AES_MECHANISM);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        }catch(GeneralSecurityException e){
            throw new CryptoException("Error loading decryption mechanism: "+e.getMessage(), e);
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
                throw new CryptoException("Error processing decryption: "+e.getMessage(), e);
            }
            if (decrypted != null) {
                output.write(decrypted);
            }
        }catch(IOException e){
            throw new CryptoException("Error processing decryption: "+e.getMessage(), e);
        }
    }

    public static byte[][] generateAesKeyIVOpenSSL(byte[] salt, byte[] data) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance(HASH_MECHANISM);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("Error loading hashing mechanism: " + e.getMessage(), e);
        }
        int count = 1;
        byte[][] both = new byte[2][];
        int nkey = 32;
        byte[] key = new byte[nkey];
        int key_ix = 0;
        int niv = 16;
        byte[] iv = new byte[niv];
        int iv_ix = 0;
        both[0] = key;
        both[1] = iv;
        byte[] md_buf = null;
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
