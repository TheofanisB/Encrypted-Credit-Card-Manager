

import java.io.IOException;
        import java.security.NoSuchAlgorithmException;
        import java.util.*;
        import java.io.*;

public class Main {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        //Δημιουργία αρχείου χρηστών
        File f = new File("Users.dat");
        if(!f.exists()) {// Checking if the file exists
            Functions.createtxt(f);//If the file doesnt exist then it calls a function to create it
        }
        RSAKeyPairGenerator keyPairGenerator = new RSAKeyPairGenerator();//Creating an RSA Object
        try {
            File f1 = new File("RSA/publicKey");
            File f2 = new File("RSA/privateKey");
            //Checking if the private key and public key files have been created

            if(!f1.exists() && !f2.exists()) {
                //When we run the app for the first time , the public and the private key are saved in the RSA folder .

                keyPairGenerator.writeToFile("RSA/publicKey", keyPairGenerator.getPublicKey().getEncoded());
                keyPairGenerator.writeToFile("RSA/privateKey", keyPairGenerator.getPrivateKey().getEncoded());
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        //Graphics Creation .
        Frames.firstFrame(keyPairGenerator);
    }
}