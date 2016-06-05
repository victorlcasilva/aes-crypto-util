package com.the008.app.rsautil;

import java.io.File;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.RSAPublicKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PEMWriter;

/**
 * RSA Key Utility.
 * 
 * @author Victor Lima de Andrade
 */
public final class RSAKeyUtil {

    public RSAKeyUtil() {
        if(Security.getProvider("BC") == null){
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Generates a RSA Private Key.
     * 
     * @param size
     *            key's size (ex: 1024, 2048, 4096)
     * @return Private Key object
     */
    public PrivateKey generatePrivateKey(int size) {
        PrivateKey key = null;
        try {
            SecureRandom random = new SecureRandom();
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
            generator.initialize(size, random);
            KeyPair pair = generator.generateKeyPair();
            key = pair.getPrivate();
        } catch (Exception e) {
            throw new RuntimeException("Error generating a " + size + " RSA Private Key.", e);
        }
        return key;
    }

    /**
     * Generates a RSA public key from a RSA Private Key.
     * 
     * @param privateKey
     *            Private Key object.
     * @return Public Key object.
     */
    public PublicKey generatePublicKey(PrivateKey privateKey) {
        PublicKey key = null;
        try {
            RSAPrivateCrtKey privkey = (RSAPrivateCrtKey) privateKey;
            RSAPublicKeySpec publicKeySpec = new java.security.spec.RSAPublicKeySpec(privkey.getModulus(), privkey.getPublicExponent());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            key = keyFactory.generatePublic(publicKeySpec);
        } catch (Exception e) {
            throw new RuntimeException("Error generating a RSA public key from a RSA private key.", e);
        }
        return key;
    }

    /**
     * Reads a RSA Private Key from an OpenSSL (PEM) compatible file.
     * 
     * @param pem
     *            Private Key file
     * @return Private Key object
     */
    public PrivateKey readPrivateKey(String file) {
        return readPrivateKey(new File(file));
    }

    /**
     * Reads a RSA Private Key from an OpenSSL (PEM) compatible file.
     * 
     * @param pem
     *            Private Key file
     * @return Private Key object
     */
    public PrivateKey readPrivateKey(File file) {
        PrivateKey key = null;
        try {
            String pem = new String(FileIO.read(file));
            PEMReader reader = new PEMReader(new StringReader(pem));
            KeyPair pair = (KeyPair) reader.readObject();
            key = pair.getPrivate();
        } catch (Exception e) {
            throw new RuntimeException("Error reading a RSA private key in PEM format.", e);
        }
        return key;
    }

    /**
     * Reads a RSA Public Key from an OpenSSL (PEM) compatible file.
     * 
     * @param pem
     *            Public Key file
     * @return Public Key object
     */
    public PublicKey readPublicKey(String file) {
        return readPublicKey(new File(file));
    }

    /**
     * Reads a RSA Public Key from an OpenSSL (PEM) compatible file.
     * 
     * @param pem
     *            Public Key file
     * @return Public Key object
     */
    public PublicKey readPublicKey(File file) {
        PublicKey key = null;
        try {
            String pem = new String(FileIO.read(file));
            PEMReader reader = new PEMReader(new StringReader(pem));
            key = (PublicKey) reader.readObject();
        } catch (Exception e) {
            throw new RuntimeException("Error reading a RSA public key in PEM format.", e);
        }
        return key;
    }

    /**
     * Writes a RSA Private Key to a file in OpenSSL (PEM) format.
     * 
     * @param key
     *            Private Key object
     * @param file
     *            Destination file
     */
    public void writePrivateKey(PrivateKey key, String file) {
        writePrivateKey(key, new File(file));
    }

    /**
     * Writes a RSA Private Key to a file in OpenSSL (PEM) format.
     * 
     * @param key
     *            Private Key object
     * @param file
     *            Destination file
     */
    public void writePrivateKey(PrivateKey key, File file) {
        try {
            StringWriter str = new StringWriter();
            PEMWriter writer = new PEMWriter(str);
            writer.writeObject(key);
            writer.close();
            String pem = str.toString();
            FileIO.write(file, pem.getBytes());
        } catch (Exception e) {
            throw new RuntimeException("Error writing a private key to a file.", e);
        }
    }

    /**
     * Writes a RSA Public Key to a file in OpenSSL (PEM) format.
     * 
     * @param key
     *            Public Key object
     * @param file
     *            Destination file
     */
    public void writePublicKey(PublicKey key, String file) {
        writePublicKey(key, new File(file));
    }

    /**
     * Writes a RSA Public Key to a file in OpenSSL (PEM) format.
     * 
     * @param key
     *            Public Key object
     * @param file
     *            Destination file
     */
    public void writePublicKey(PublicKey key, File file) {
        try {
            StringWriter str = new StringWriter();
            PEMWriter writer = new PEMWriter(str);
            writer.writeObject(key);
            writer.close();
            String pem = str.toString();
            FileIO.write(file, pem.getBytes());
        } catch (Exception e) {
            throw new RuntimeException("Error saving a public key to a file.", e);
        }
    }

}
