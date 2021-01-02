package com.the008.app.cryptoutil.tests.generator;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import org.junit.Assert;
import org.junit.Test;

import com.the008.app.cryptoutil.generator.SecureRandomGenerator;

@Slf4j
public class SecureRandomPasswordGenerationTest {

    private String password;
    
    @Test
    public void test01_GeneratePassword(){
        log.debug("Testing Secure Random password generation");
        password = SecureRandomGenerator.generatePassword();
        log.debug("Generated password ("+password.length()+" characters) encoded in Base64: "+password);
        Assert.assertEquals("The generated password should be "+(SecureRandomGenerator.DEFAULT_PASSWORD_SIZE*8)+" bits", SecureRandomGenerator.DEFAULT_PASSWORD_SIZE, Base64.decodeBase64(password).length);
    }
    
}
