package com.the008.app.cryptoutil.tests.generator;

import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;
import org.junit.Assert;
import org.junit.Test;

import com.the008.app.cryptoutil.generator.SecureRandomGenerator;

public class SecureRandomPasswordGenerationTest {

    private Logger log = Logger.getLogger(getClass());
    private String password;
    
    @Test
    public void test01_GeneratePassword(){
        log.info("Testing Secure Random password generation");
        password = SecureRandomGenerator.generatePassword();
        log.info("Generated password ("+password.length()+" characters) encoded in Base64: "+password);
        Assert.assertEquals("The generated password should be "+(SecureRandomGenerator.DEFAULT_PASSWORD_SIZE*8)+" bits", SecureRandomGenerator.DEFAULT_PASSWORD_SIZE, Base64.decodeBase64(password).length);
    }
    
}
