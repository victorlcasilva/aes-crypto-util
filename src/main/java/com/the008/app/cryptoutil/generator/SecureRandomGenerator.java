package com.the008.app.cryptoutil.generator;

import java.security.SecureRandom;

import org.apache.commons.codec.binary.Base64;

public abstract class SecureRandomGenerator {

    public static final int DEFAULT_PASSWORD_SIZE = 32; /* 256 bits */
    private static final String SECURE_RANDOM_MECHANISM = "SHA1PRNG";
    
    public static byte[] generateRandom(int size) {
        try {
            SecureRandom sr = SecureRandom.getInstance(SECURE_RANDOM_MECHANISM);
            byte[] rnd = new byte[size];
            sr.nextBytes(rnd);
            return rnd;
        } catch (Exception e) {
            throw new RuntimeException("Error generating secure random number: " + e.getMessage(), e);
        }
    }
    
    public static String generatePassword(){
        return generatePassword(DEFAULT_PASSWORD_SIZE);
    }
    
    public static String generatePassword(int size){
        return Base64.encodeBase64String(generateRandom(size));
    }
    
}
