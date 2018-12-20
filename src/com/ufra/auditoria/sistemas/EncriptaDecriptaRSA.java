package com.ufra.auditoria.sistemas;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class EncriptaDecriptaRSA {

    public static final String PATH = System.clearProperty("user.home");
    public static final String ALGORITHM = "RSA";
    public static final String PATH_CHAVE_PRIVADA = PATH + "/private.key";
    public static final String PATH_CHAVE_PUBLICA = PATH + "/public.key";

    public static void generateKeys() throws IOException {
        try {
            final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
            keyGen.initialize(1024);
            final KeyPair key = keyGen.generateKeyPair();

            File chavePrivadaFile = new File(PATH_CHAVE_PRIVADA);
            File chavePublicaFile = new File(PATH_CHAVE_PUBLICA);

            if (chavePrivadaFile.getParentFile() != null) {
                chavePrivadaFile.getParentFile().mkdirs();
            }

            chavePrivadaFile.createNewFile();

            if (chavePublicaFile.getParentFile() != null) {
                chavePublicaFile.getParentFile().mkdirs();
            }

            chavePublicaFile.createNewFile();

            try (ObjectOutputStream chavePublicaOS = new ObjectOutputStream(
                    new FileOutputStream(chavePublicaFile))) {
                chavePublicaOS.writeObject(key.getPublic());
            }

            try (ObjectOutputStream chavePrivadaOS = new ObjectOutputStream(
                    new FileOutputStream(chavePrivadaFile))) {
                chavePrivadaOS.writeObject(key.getPrivate());
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace(System.err);
        }
    }

    public static void setup() throws IOException {
        if (!ifExistKeys()) {
            generateKeys();
        }
    }

    public static boolean ifExistKeys() {
        File chavePrivada = new File(PATH_CHAVE_PRIVADA);
        File chavePublica = new File(PATH_CHAVE_PUBLICA);
        boolean resposta = false;

        if (chavePrivada.exists() && chavePublica.exists()) {
            resposta = true;
        }

        return resposta;
    }

    public static byte[] criptografa(String texto) throws IOException, ClassNotFoundException {
        byte[] cipherText = null;

        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream(PATH_CHAVE_PUBLICA));
            PublicKey chavePublica = (PublicKey) inputStream.readObject();
            cipher.init(Cipher.ENCRYPT_MODE, chavePublica);
            cipherText = cipher.doFinal(texto.getBytes());
        } catch (InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
            e.printStackTrace(System.err);
        }

        return cipherText;
    }

    public static String decriptografa(byte[] texto) throws FileNotFoundException, IOException, ClassNotFoundException {
        byte[] dectyptedText = null;

        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream(PATH_CHAVE_PRIVADA));
            PrivateKey chavePrivada = (PrivateKey) inputStream.readObject();
            cipher.init(Cipher.DECRYPT_MODE, chavePrivada);
            dectyptedText = cipher.doFinal(texto);
        } catch (InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
            e.printStackTrace(System.err);
        }

        return new String(dectyptedText);
    }

}
