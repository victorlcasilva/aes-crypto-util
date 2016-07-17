package com.the008.app.cryptoutil.rsa;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;

import com.the008.app.cryptoutil.util.CryptoException;

/**
 * RSA Key Utility.
 * 
 * @author Victor Lima de Andrade
 */
public abstract class RSAKeyUtil {

    public static String encodePublicKeySSH(PublicKey publicKey, String user) {
        String sshKey = null;
        try {
            RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
            ByteArrayOutputStream byteOs = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(byteOs);
            dos.writeInt("ssh-rsa".getBytes().length);
            dos.write("ssh-rsa".getBytes());
            dos.writeInt(rsaPublicKey.getPublicExponent().toByteArray().length);
            dos.write(rsaPublicKey.getPublicExponent().toByteArray());
            dos.writeInt(rsaPublicKey.getModulus().toByteArray().length);
            dos.write(rsaPublicKey.getModulus().toByteArray());
            sshKey = new String(Base64.encodeBase64(byteOs.toByteArray()));
            sshKey = "ssh-rsa " + sshKey + " " + user;
        } catch (Exception e) {
            throw new CryptoException("Error encoding RSA SSH key", e);
        }
        return sshKey;
    }

    public static PublicKey readPublicKey(File file) {
        loadBCProvider();
        try ( BufferedReader reader = new BufferedReader(new FileReader(file));
              PEMParser parser = new PEMParser(reader)) {
            SubjectPublicKeyInfo pbinfo = (SubjectPublicKeyInfo) parser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            return converter.getPublicKey(pbinfo);
        } catch (Exception e) {
            throw new CryptoException("Error reading a RSA public key in PEM format", e);
        }
    }

    public static PublicKey extractPublicKey(PrivateKey pk) {
        PublicKey key = null;
        try {
            RSAPrivateCrtKey privkey = (RSAPrivateCrtKey) pk;
            RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(privkey.getModulus(), privkey.getPublicExponent());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            key = keyFactory.generatePublic(publicKeySpec);
        } catch (Exception e) {
            throw new CryptoException("Error extracting a RSA public key from a RSA private key.", e);
        }
        return key;
    }

    public static void writePublicKeyPEM(PublicKey publicKey, File output) {
        try (JcaPEMWriter writer = new JcaPEMWriter(new FileWriter(output))){
            writer.writeObject(publicKey);
        } catch (IOException e) {
            throw new CryptoException("Error writing public key in PEM format", e);
        }
    }

    public static void writePrivateKeyPEM(PrivateKey privateKey, File output) {
        writePrivateKeyPEM(privateKey, output, null);
    }

    public static void writePrivateKeyPEM(PrivateKey privateKey, File output, String password) {
        try (JcaPEMWriter writer = new JcaPEMWriter(new FileWriter(output))){
            if (password != null) {
                writer.writeObject(privateKey, new JcePEMEncryptorBuilder("DES-EDE3-CBC").build(password.toCharArray()));
            } else {
                writer.writeObject(privateKey);
            }
        } catch (IOException e) {
            throw new CryptoException("Error writing private key in PEM format", e);
        }
    }

    public static PrivateKey readPrivateKeyPEM(File file) {
        return readPrivateKeyPEM(file, null);
    }

    public static PrivateKey readPrivateKeyPEM(File file, String password) {
        loadBCProvider();
        PEMKeyPair keyPair = null;
        try ( BufferedReader reader = new BufferedReader(new FileReader(file));
              PEMParser parser = new PEMParser(reader)) {
            Object obj = parser.readObject();
            if (obj instanceof PEMEncryptedKeyPair) {
                if (password == null) {
                    throw new IllegalArgumentException("No password provided to decrypt private key");
                }
                PEMDecryptorProvider decryptorProvider = new JcePEMDecryptorProviderBuilder().build(password.toCharArray());
                PEMEncryptedKeyPair encryptedKeyPair = (PEMEncryptedKeyPair) obj;
                keyPair = encryptedKeyPair.decryptKeyPair(decryptorProvider);
            } else {
                keyPair = (PEMKeyPair) obj;
            }
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            return converter.getPrivateKey(keyPair.getPrivateKeyInfo());
        } catch (Exception e) {
            throw new CryptoException("Error reading a RSA private key in PEM format", e);
        }
    }

    private static void loadBCProvider() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

}
