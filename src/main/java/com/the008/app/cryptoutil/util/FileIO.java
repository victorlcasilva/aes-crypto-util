package com.the008.app.cryptoutil.util;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * Input/Output Utility.
 * 
 * @author Victor Lima de Andrade <victor.the008@gmail.com>
 */
public abstract class FileIO {

    public static byte[] read(String file) throws IOException {
        return read(new File(file));
    }

    public static void write(String name, byte[] data) throws IOException {
        write(new File(name), data);
    }

    public static byte[] read(File file) throws IOException {
        byte[] retorno = null;
        try (BufferedInputStream in = new BufferedInputStream(new FileInputStream(file))) {
            retorno = new byte[(int) file.length()];
            in.read(retorno);
        } catch (Exception e) {
            throw new IOException("Error reading file.", e);
        }
        return retorno;
    }

    public static void write(File file, byte[] data) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(data);
        } catch (Exception e) {
            file.delete();
            throw new IOException("Error writing file.", e);
        }
    }

}
