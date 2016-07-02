package com.the008.app.cryptoutil;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

/**
 * Input/Output Utility.
 * 
 * @author Victor Lima de Andrade <victor.the008@gmail.com>
 */
public abstract class FileIO {

    public static byte[] read(String file) {
        return read(new File(file));
    }
    
    public static void write(String name, byte[] data){
        write(new File(name), data);
    }
    
    public static byte[] read(File file){
        byte[] retorno = null;
        BufferedInputStream in = null;
        try {
            retorno = new byte[(int) file.length()];
            in = new BufferedInputStream(new FileInputStream(file));
            in.read(retorno);
        } catch (Exception e) {
            throw new RuntimeException("Error reading file.", e);
        } finally {
            close(in);
        }
        return retorno;
    }
    
    public static void write(File file, byte[] data) {
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(file);
            fos.write(data);
        } catch (Exception e) {
            try {
                file.delete();
            } catch (Exception e1) {
            }
            throw new RuntimeException("Error writing file.", e);
        } finally {
            close(fos);
        }
    }

    private static void close(BufferedInputStream in) {
        if (in != null) {
            try {
                in.close();
            } catch (Exception e) {
            }
        }
    }

    private static void close(FileOutputStream fos) {
        if (fos != null) {
            try {
                fos.close();
            } catch (Exception e) {
            }
        }
    }
}
