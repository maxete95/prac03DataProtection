import prac02DataProtection.RSALibrary;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Scanner;

public class SimpleSec {


    /**
    - First part: generate the pair of RSA keys and cipher the private one with the passphrase
        given by the user.
     */
    public static void g()
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        RSALibrary rsaLibrary = new RSALibrary();
        byte[] privateKeyCipher = null;

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
    }

    /**
     - Second part:
        - Encrypting the input text with the passphrase using the AES library
        - Encrypting the passphrase with the public key
        - Doing the concatenation and
     @param sourceFile The path of the file to be encrypted
     @param destinationFile The path of the encrypted file
     */
    public static void e(String sourceFile, String destinationFile)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, ClassNotFoundException{

        byte[] privateKeyBytes = null;
        byte[] cipheredText = null;

        RSALibrary rsaLibrary = new RSALibrary();

        // Get the password from the user
        System.out.println("Please, introduce a secret passphrase: ");
        Scanner scanner = new Scanner(System.in);
        String passphrase = scanner.nextLine();

        // Decrytp the private key
        byte[] privateKeyCipher = Files.readAllBytes(Paths.get(rsaLibrary.PRIVATE_KEY_FILE));
        //  privateKeyBytes = SymmetricCipher.decryptCBC(privateKeyCipher, passphrase.getBytes());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));

        // Read the data from the source file
        byte[] sourceFileByte = Files.readAllBytes(Paths.get(sourceFile));

        //Encrypt the plaintext with the passphrase using AES
//        cipheredText = SymmetricCipher.encryptCBC(sourceFileBytes, passphrase.getBytes());

        // Encrypt the passphrase with the public key
        FileInputStream filePublicKey = new FileInputStream(rsaLibrary.PUBLIC_KEY_FILE);
        ObjectInputStream oisPublicKey = new ObjectInputStream(filePublicKey);
        PublicKey publicKey = (PublicKey) oisPublicKey.readObject();
        byte[] passphraseEncrypted = rsaLibrary.encrypt(passphrase.getBytes(), publicKey);

        // Concatenation of ciphered text and encrypted passphrase
        byte[] concatenated = new byte[passphraseEncrypted.length + cipheredText.length];
        System.arraycopy(passphraseEncrypted, 0, concatenated, 0, passphraseEncrypted.length);
        System.arraycopy(cipheredText, 0, concatenated, passphraseEncrypted.length, cipheredText.length);

        // Signing process of the concatenated text and writing in destination file
        byte[] signedConcatenated = rsaLibrary.sign(concatenated, privateKey);
        FileOutputStream keyfos = new FileOutputStream(destinationFile);
        ObjectOutputStream oos = new ObjectOutputStream(keyfos);
        oos.writeObject(new String(signedConcatenated));
        oos.close();



    }

    public static void main(String[] args) {


        if (!args[0].isEmpty() && !args[1].isEmpty()) {
            try {

                String sourceFile = args[0];
                String destinationFile = args[1];

                g();

                /*
                - Second part:
                    - Encrypting the input text with the passphrase using the AES library
                    - Encrypting the passphrase with the public key
                    - Doing the concatenation and
                 */

            } catch (Exception e) {
                System.err.println("Error in run: " + e.toString());
            }

        } else {
            System.out.println("You have to introduce the path of the source and destination files");
        }

    }
}
