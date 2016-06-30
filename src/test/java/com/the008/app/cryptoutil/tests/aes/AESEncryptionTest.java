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

import com.the008.app.cryptoutil.AESOpenSSLKeyUtil;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class AESEncryptionTest {

    private Logger log = Logger.getLogger(getClass());
    private String text = "Hello World";
    private String password;
    private String encrypted;
    
    @Before
    public void configure(){
        password = AESOpenSSLKeyUtil.generatePassword();
    }
    
    @Test
    public void test02_Encrypt(){
        log.info("Testing AES 256-bits encryption");
        log.info("Generated password: "+password);
        ByteArrayInputStream bai = new ByteArrayInputStream(text.getBytes());
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        AESOpenSSLKeyUtil.encrypt(bai, password, bao);
        encrypted = Base64.encodeBase64String(bao.toByteArray());
        log.info("Plain message: "+text);
        log.info("Encrypted message: "+encrypted);
        Assert.assertNotNull("The encrypted message should not be NULL", encrypted);
    }
    
}
