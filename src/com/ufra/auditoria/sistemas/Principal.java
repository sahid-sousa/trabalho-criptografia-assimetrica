package com.ufra.auditoria.sistemas;

import java.io.IOException;
import java.util.Arrays;
import java.util.Scanner;

public class Principal {

    public static void main(String[] args) {
        Scanner entrada = new Scanner(System.in);
        try {
            EncriptaDecriptaRSA.setup();
            System.out.println("Informe um texto: ");
            String menssagem = entrada.next();
            
            byte[] textoCriptografado = EncriptaDecriptaRSA.criptografa(menssagem);
            String textoPuro = EncriptaDecriptaRSA.decriptografa(textoCriptografado);
            
            System.out.println("Menssagem: " + menssagem);
            System.out.println("Mensagem Criptografada: " + Arrays.toString(textoCriptografado));
            System.out.println("Mensagem Decriptografada: " + textoPuro);
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace(System.err);
        }
    }

}
