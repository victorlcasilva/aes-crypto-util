package com.the008.app.rsautil;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

/**
 * RSA Utility.
 * 
 * @author Victor Lima de Andrade
 */
public final class RSAUtil {

    private final String algorith = "RSA/ECB/PKCS1Padding";
    private RSAKeyUtil util;
    
    private PrivateKey privateKey;
    private PublicKey publicKey;
    
    private Cipher encryptor;
    private Cipher decryptor;
    
    private Signature signer;
    private Signature verifier;
    
    /**
     * Creates a new instance of the RSA Utility.
     * <p><strong><font color="red">
     * WARNING: without providing a private key,
     * it's not possible to decrypt an information or create a digital signature.
     * </font></strong></p>
     * @param publicKey RSA Public Key
     */
    public RSAUtil(PublicKey publicKey){
        this.publicKey = publicKey;
    }
    
    /**
     * Creates a new instance of the RSA Utility.
     * @param privateKey RSA Private Key.
     */
    public RSAUtil(PrivateKey privateKey){
        this.privateKey = privateKey;
        this.util = new RSAKeyUtil();
    }
    
    /**
     * Creates a new instance of the RSA Utility.
     * @param privateKey RSA Private Key.
     * @param publicKey RSA Public Key.
     */
    public RSAUtil(PrivateKey privateKey, PublicKey publicKey){
        this(privateKey);
        this.publicKey = publicKey;
    }
    
    public byte[] encryptLong(byte[] information){
        byte[] encrypted = null;
        try{
            if(encryptor == null){
                loadEncryptionMechanism();
            }
            encrypted = blockCipher(encryptor, information,Cipher.ENCRYPT_MODE);
        }catch(Exception e){
            throw new RuntimeException("Error encrypting information.", e);
        }
        return encrypted;
    }
    
    private byte[] blockCipher(Cipher cipher, byte[] bytes, int mode) throws IllegalBlockSizeException, BadPaddingException{
        // string initialize 2 buffers.
        // scrambled will hold intermediate results
        byte[] scrambled = new byte[0];

        // toReturn will hold the total result
        byte[] toReturn = new byte[0];
        // if we encrypt we use 100 byte long blocks. Decryption requires 128 byte long blocks (because of RSA)
        int length = (mode == Cipher.ENCRYPT_MODE)? 100 : 128;

        // another buffer. this one will hold the bytes that have to be modified in this step
        byte[] buffer = new byte[length];

        for (int i=0; i< bytes.length; i++){

            // if we filled our buffer array we have our block ready for de- or encryption
            if ((i > 0) && (i % length == 0)){
                //execute the operation
                scrambled = cipher.doFinal(buffer);
                // add the result to our total result.
                toReturn = append(toReturn,scrambled);
                // here we calculate the length of the next buffer required
                int newlength = length;

                // if newlength would be longer than remaining bytes in the bytes array we shorten it.
                if (i + length > bytes.length) {
                     newlength = bytes.length - i;
                }
                // clean the buffer array
                buffer = new byte[newlength];
            }
            // copy byte into our buffer.
            buffer[i%length] = bytes[i];
        }

        // this step is needed if we had a trailing buffer. should only happen when encrypting.
        // example: we encrypt 110 bytes. 100 bytes per run means we "forgot" the last 10 bytes. they are in the buffer array
        scrambled = cipher.doFinal(buffer);

        // final step before we can return the modified data.
        toReturn = append(toReturn,scrambled);

        return toReturn;
    }
    
    private byte[] append(byte[] prefix, byte[] suffix){
        byte[] toReturn = new byte[prefix.length + suffix.length];
        for (int i=0; i< prefix.length; i++){
            toReturn[i] = prefix[i];
        }
        for (int i=0; i< suffix.length; i++){
            toReturn[i+prefix.length] = suffix[i];
        }
        return toReturn;
    }
    
    /**
     * Encrypts an information.
     * @param information Information to be encrypted.
     * @return Encrypted information.
     */
    public byte[] encrypt(byte[] information){
        byte[] encrypted = null;
        try{
            if(encryptor == null){
                loadEncryptionMechanism();
            }
            encrypted = encryptor.doFinal(information);
        }catch(Exception e){
            throw new RuntimeException("Error encrypting information.", e);
        }
        return encrypted;
    }
    
    /**
     * Decrypts an information encrypted using RSA.
     * @param Encrypted information. 
     * @return Decrypted information.
     */
    public byte[] decrypt(byte[] encrypted){
        byte[] information = null;
        try{
            if(decryptor == null){
                loadDecryptionMechanism();
            }
            information = decryptor.doFinal(encrypted);
        }catch(Exception e){
            throw new RuntimeException("Error decrypting information.", e);
        }
        return information;
    }
    
    /**
     * Creates a digital signature that can be used to verify an information's authenticity.
     * @param information Information.
     * @return Information's digital signature.
     */
    public byte[] createDigitalSignature(byte[] information){
        byte[] digitalSignature = null;
        try{
            if(signer == null){
                loadSigningMechanism();
            }
            signer.update(information);
            digitalSignature = signer.sign();
        }catch(Exception e){
            throw new RuntimeException("Error creating a digital signature.", e);
        }
        return digitalSignature;
    }
    
    /**
     * Verifies an information's digital signature.
     * @param information Information.
     * @param digitalSignature Information's digital signature.
     * @return <strong>true</strong> if the digital signature is valid. <strong>false</strong> otherwise.
     */
    public boolean verifyDigitalSignature(byte[] information, byte[] digitalSignature){
        boolean isValid = false;
        try{
            if(verifier == null){
                loadSignaturesVerifyingMechanism();
            }
            verifier.update(information);
            isValid = verifier.verify(digitalSignature);
        }catch(Exception e){
            throw new RuntimeException("Error verifying an information's digital signature.", e);
        }
        return isValid;
    }
    
    private void loadEncryptionMechanism() {
        try{
            if(publicKey == null){
                publicKey = util.generatePublicKey(privateKey);
            }
            encryptor = Cipher.getInstance(algorith, "BC");
            encryptor.init(Cipher.ENCRYPT_MODE, publicKey);
        }catch(Exception e){
            throw new RuntimeException("Error loading encryption mechanism.", e);
        }
    }
    
    private void loadDecryptionMechanism(){
        try{
            if(privateKey == null){
                throw new IllegalStateException("No private key was provided. It's not possible to decrypt an information without a private key.");
            }
            decryptor = Cipher.getInstance(algorith, "BC");
            decryptor.init(Cipher.DECRYPT_MODE, privateKey);
        }catch(Exception e){
            throw new RuntimeException("Error loading decryption mechanism.", e);
        }
    }
    
    private void loadSigningMechanism(){
        try{
            if(privateKey == null){
                throw new IllegalStateException("No private key was provided. It's not possible to create a digital signature without a private key.");
            }
            signer = Signature.getInstance("SHA1withRSA");
            signer.initSign(privateKey);
        }catch(Exception e){
            throw new RuntimeException("Error loading signing mechanism.", e);
        }
    }
    
    private void loadSignaturesVerifyingMechanism(){
        try{
            if(publicKey == null){
                publicKey = util.generatePublicKey(privateKey);
            }
            verifier = Signature.getInstance("SHA1withRSA");
            verifier.initVerify(publicKey);
        }catch(Exception e){
            throw new RuntimeException("Error loading signature's verifying mechanism.", e);
        }
    }
}
