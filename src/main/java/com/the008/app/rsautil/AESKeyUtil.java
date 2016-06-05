/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.the008.app.rsautil;

import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.apache.commons.codec.binary.Hex;

/**
 *
 * @author victor
 */
public class AESKeyUtil {
    
    public static void main(String[] args) throws Exception{
        SecureRandom random = new SecureRandom();
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256, random);
        SecretKey key = generator.generateKey();
        byte[] rawkey = key.getEncoded();
        String str_key = Hex.encodeHexString(rawkey);
        System.out.println("> Raw Key ("+str_key.length()+"): "+str_key);
        String info = "Victor Lima Costa de Andrade e Silva";
        Cipher enc = Cipher.getInstance("AES");
        enc.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = enc.doFinal(info.getBytes());
        String str_enc = Hex.encodeHexString(encrypted);
        System.out.println("> Encrypted ("+str_enc.length()+"): "+str_enc);
        Cipher dec = Cipher.getInstance("AES");
        dec.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = dec.doFinal(encrypted);
        String str_dec = new String(decrypted);
        System.out.println("> Decrypted ("+str_dec.length()+"): "+str_dec);
    }
    
}
