package com.the008.app.cryptoutil.tests.aes;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import org.junit.Assert;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import com.the008.app.cryptoutil.aes.AESCryto;
import com.the008.app.cryptoutil.generator.SecureRandomGenerator;

@Slf4j
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class AESDecryptionTest {

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
        log.debug("Testing AES 256-bits decryption");
        log.debug("Generated password: "+password);
        log.debug("Plain message: "+text);
        log.debug("Encrypted message: "+encrypted);
        ByteArrayInputStream bai = new ByteArrayInputStream(Base64.decodeBase64(encrypted));
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        AESCryto.decrypt(bai, password, bao);
        decrypted = new String(bao.toByteArray());
        log.debug("Decrypted message: "+decrypted);
        Assert.assertEquals("The decrypted message should be the same as the plain message", decrypted, text);
    }
    
}
