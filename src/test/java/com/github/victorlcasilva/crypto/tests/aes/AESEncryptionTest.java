package com.github.victorlcasilva.crypto.tests.aes;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import com.github.victorlcasilva.crypto.aes.AESCryto;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import org.junit.Assert;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import com.github.victorlcasilva.crypto.generator.SecureRandomGenerator;

@Slf4j
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class AESEncryptionTest {

    private String text = "Hello World";
    private String password;
    private String encrypted;
    
    @Before
    public void configure(){
        password = SecureRandomGenerator.generatePassword();
    }
    
    @Test
    public void test02_Encrypt(){
        log.debug("Testing AES 256-bits encryption");
        log.debug("Generated password: "+password);
        ByteArrayInputStream bai = new ByteArrayInputStream(text.getBytes());
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        AESCryto.encrypt(bai, password, bao);
        encrypted = Base64.encodeBase64String(bao.toByteArray());
        log.debug("Plain message: "+text);
        log.debug("Encrypted message: "+encrypted);
        Assert.assertNotNull("The encrypted message should not be NULL", encrypted);
    }
    
}
