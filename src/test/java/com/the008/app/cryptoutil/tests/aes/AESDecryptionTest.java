package com.the008.app.cryptoutil.tests.aes;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;
import org.junit.Assert;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import com.the008.app.cryptoutil.aes.AESCryto;
import com.the008.app.cryptoutil.generator.SecureRandomGenerator;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class AESDecryptionTest {

    private Logger log = Logger.getLogger(getClass());
    private String text = "Hello World";
    private String password;
    private String encrypted;
    private String decrypted;
    
    @Before
    public void configure(){
        password = SecureRandomGenerator.generatePassword();
        ByteArrayInputStream bai = new ByteArrayInputStream(text.getBytes());
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        AESCryto.encrypt(bai, password, bao);
        encrypted = Base64.encodeBase64String(bao.toByteArray());
    }
    
    @Test
    public void test_Decrypt(){
        log.info("Testing AES 256-bits decryption");
        log.info("Generated password: "+password);
        log.info("Plain message: "+text);
        log.info("Encrypted message: "+encrypted);
        ByteArrayInputStream bai = new ByteArrayInputStream(Base64.decodeBase64(encrypted));
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        AESCryto.decrypt(bai, password, bao);
        decrypted = new String(bao.toByteArray());
        log.info("Decrypted message: "+decrypted);
        Assert.assertEquals("The decrypted message should be the same as the plain message", decrypted, text);
    }
    
}
