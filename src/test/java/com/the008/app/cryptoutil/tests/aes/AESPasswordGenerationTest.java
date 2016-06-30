package com.the008.app.cryptoutil.tests.aes;

import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;
import org.junit.Assert;
import org.junit.Test;

import com.the008.app.cryptoutil.AESOpenSSLKeyUtil;

public class AESPasswordGenerationTest {

    private Logger log = Logger.getLogger(getClass());
    private String password;
    
    @Test
    public void test01_GeneratePassword(){
        log.info("Testing AES 256-bits password generation");
        password = AESOpenSSLKeyUtil.generatePassword();
        log.info("Generated password: "+password);
        Assert.assertEquals("The generated password should be 256 bits", AESOpenSSLKeyUtil.AES_KEY_SIZE, Base64.decodeBase64(password).length);
    }
    
}
