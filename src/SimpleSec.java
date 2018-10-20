import prac02DataProtection.RSALibrary;

import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Scanner;

public class SimpleSec {

    public static void main(String []args) {
        try {
            RSALibrary rsaLibrary = new RSALibrary();
            byte[] privateKeyCipher = null;

            /*
            - First part: generate the pair of RSA keys and cipher the private one with the passphrase
                given by the user.
             */

            rsaLibrary.generateKeys();

            byte[] privateKeyBytes = Files.readAllBytes(Paths.get(rsaLibrary.PRIVATE_KEY_FILE));

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));

            System.out.println("Please, introduce a secret passphrase: ");
            Scanner scanner = new Scanner(System.in);
            String passphrase = scanner.nextLine();

//            privateKeyCipher = SymmetricCipher.encryptCBC(privateKey.getEncoded(), passphrase.getBytes());

            FileOutputStream fosPrivateKey = new FileOutputStream(rsaLibrary.PRIVATE_KEY_FILE);
            fosPrivateKey.write(privateKeyCipher);
            fosPrivateKey.close();




        } catch (Exception e) {
            System.err.println("Error in run: " + e.toString());
        }
    }
}
