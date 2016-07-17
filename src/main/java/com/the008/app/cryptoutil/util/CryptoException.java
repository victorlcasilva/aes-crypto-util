package com.the008.app.cryptoutil.util;

public class CryptoException extends RuntimeException{

    private static final long serialVersionUID = 1L;

    public CryptoException(String message) {
        super(message);
    }
    
    public CryptoException(String message, Throwable t) {
        super(message, t);
    }
    
}
