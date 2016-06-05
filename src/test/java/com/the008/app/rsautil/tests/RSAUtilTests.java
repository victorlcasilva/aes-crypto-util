package com.the008.app.rsautil.tests;

import java.security.Provider;
import java.security.Security;

import org.apache.commons.codec.binary.Hex;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.the008.app.rsautil.RSAKeyUtil;
import com.the008.app.rsautil.RSAUtil;


/**
 * Testing the RSA Utility.
 * 
 * @author Victor Lima de Andrade
 */
public class RSAUtilTests {

    private RSAUtil rsa;
    private byte[] information = "RSA Utility".getBytes();
    private byte[] encrypted;
    private byte[] decrypted;
    private byte[] signature;
    private boolean validSignature;
    
    @Before
    public void init(){
        rsa = new RSAUtil(new RSAKeyUtil().generatePrivateKey(2048));
        System.out.println("> Information: "+(new String(information)));
    }
    
    @Test
    public void test01_encrypt(){
        encrypted = rsa.encrypt(information);
        System.out.println("> Encrypted: "+Hex.encodeHexString(encrypted));
        Assert.assertNotNull(encrypted);
    }
    
    @Test
    public void test02_decrypt(){
        if(encrypted == null){
            test01_encrypt();
        }
        decrypted = rsa.decrypt(encrypted);
        System.out.println("> Decrypted: "+(new String(decrypted)));
        Assert.assertArrayEquals(information, decrypted);
    }
    
    @Test
    public void test03_createDigitalSignature(){
        signature = rsa.createDigitalSignature(information);
        System.out.println("> Signature: "+Hex.encodeHexString(signature));
        Assert.assertNotNull(signature);
    }
    
    @Test
    public void test04_verifyDigitalSignature(){
        if(signature == null){
            test03_createDigitalSignature();
        }
        validSignature = rsa.verifyDigitalSignature(information, signature);
        System.out.println("> Valid Signature: "+validSignature);
        Assert.assertTrue(validSignature);
    }
    
    @Test
    public void test05_encryptLongData(){
        byte[] longInfo = "Veeeeeeeery looooooooooooooooooooooooong information. Veeeeeeeery looooooooooooooooooooooooong information. Veeeeeeeery looooooooooooooooooooooooong information. Veeeeeeeery looooooooooooooooooooooooong information. Veeeeeeeery looooooooooooooooooooooooong information. Veeeeeeeery looooooooooooooooooooooooong information. Veeeeeeeery looooooooooooooooooooooooong information. Veeeeeeeery looooooooooooooooooooooooong information. ".getBytes();
        System.out.println("Long Info: "+longInfo.length);
        encrypted = rsa.encryptLong(longInfo);
        String str_encrypted = Hex.encodeHexString(encrypted);
        System.out.println("Long Info ("+str_encrypted.length()+"): "+str_encrypted);
        Assert.assertNotNull(encrypted);
    }
    
}
