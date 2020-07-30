import org.w3c.dom.ls.LSOutput;

import javax.crypto.*;
import javax.swing.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.ArrayList;
import java.util.Arrays;

import static java.lang.Integer.parseInt;

public class Functions {
    protected static final String EMAIL_PATTERN = "^[_A-Za-z0-9-\\+]+(\\.[_A-Za-z0-9-]+)*@" + "[A-Za-z0-9-]+(\\.[A-Za-z0-9]+)*(\\.[A-Za-z]{2,})$";// email pattern
    protected static final String CVV_PATTERN = "([0-9]{3}){1}$";//cvv pattern
    protected static final String CC_PATTERN = "([0-9]{16}){1}";//credit card number pattern
    protected static final String PASSWORD_PATTERN = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=])(?=\\S+$).{8,}$";//password pattern

    protected static FileOutputStream fileOut;// Create a file  stream so we can write data to a file
    protected static ObjectOutputStream objectOut;// Creating an object stream so we can write objects to a file
    protected static FileInputStream fileIn;// Creating an input stream so we can read from a file
    protected static ObjectInputStream objectIn;// Creating an input stream so  we can read objects from a file

    protected static FileOutputStream fileOutuser;//Creating a file so we can write in it Δημιουργία ενός αρχείου ώστε να γράψω σε αυτό
    protected static ObjectOutputStream objectOutuser;
    protected static FileInputStream fileInuser;
    protected static ObjectInputStream objectInuser;
    protected static File fuser;

    protected static ArrayList<Cards> searchcard = new ArrayList<>();

    // Function that creates the streams to the file

    protected static void createtxt(File f) {
        try {
            fileOut = new FileOutputStream(f);
            objectOut = new ObjectOutputStream(fileOut);
        } catch (IOException e) {
            System.out.println("Write error");
        }
    }

    //Functio that checks if the username matches a username in the username file
    //returns true or false
    protected static boolean checkusername(Account acc) {
        Object obj = null;
        try {
            fileIn = new FileInputStream("Users.dat");
            objectIn = new ObjectInputStream(fileIn);
            do {
                obj = objectIn.readObject();
                if (obj instanceof Account) {
                    if ((((Account) obj).getUsername().equals(acc.getUsername()))) {
                        return false;
                    }
                }
            } while (obj != null);
            objectIn.close();
            fileIn.close();
        } catch (IOException | ClassNotFoundException ex) {
            return true;
        }

        return true;
    }

    //Συνάρτηση που χρησημοποιείται κατά το login ώστε να ελέγξει αν τα στοιχεία που εισάγει ο χρήστης αντιστοιχούν σε κάποιον χρήστη μέσα από το αρχείο χρηστών
    //επιστρέφει τον user  αν υπάρχει αλλιώς επιστρέφει null
    //Function that is used during the login process  , checks the user's credentials if they match with one in the file
    // returns the user and if there's no match it returns null
    protected static Account checkaccount(Account user, RSAKeyPairGenerator keyPairGenerator)
            throws IOException, ClassNotFoundException, IllegalBlockSizeException, InvalidKeyException,
            BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        Object obj;
        try {
            fileIn = new FileInputStream("Users.dat");
            objectIn = new ObjectInputStream(fileIn);
            do {
                obj = objectIn.readObject();
                if (obj instanceof Account) {
                    if (((Account) obj).getUsername().equals(user.getUsername())) {
                        user.setSalt(((Account) obj).getSalt());
                        user = get_SHA_256_SecurePassword(user, keyPairGenerator);
                        if (user.getHashpw().equals(((Account) obj).getHashpw())) {
                            user = (Account) obj;
                            byte[] recovered_message = Functions.decrypt(keyPairGenerator.getPrivateKey(), user.getSymkey());
                            user.setSymkey(recovered_message);
                            objectIn.close();
                            fileIn.close();
                            return user;
                        }
                    }
                }
            } while (obj != null);
        } catch (IOException e) {
            e.printStackTrace();
        }
        objectIn.close();
        fileIn.close();
        return null;
    }

    //Function that was used to print all the users' info
    //This allows us to ensure that new users were added to the file
    protected static void display(RSAKeyPairGenerator keyPairGenerator) {
        Object obj = null;
        try {
            fileIn = new FileInputStream("Users.dat");
            objectIn = new ObjectInputStream(fileIn);
            do {
                obj = objectIn.readObject();
                if (obj instanceof Account) {
                    System.out.println("\n\nDisplay obj: " + obj.toString());
                } else {
                    System.out.println("\n\nelse " + obj.toString());
                }
            } while (obj != null);
            objectIn.close();
            fileIn.close();
        } catch (FileNotFoundException ex) {
            //Logger.getLogger(Register.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException | ClassNotFoundException ex) {
            //Logger.getLogger(Register.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    //Function that adds a new account to the users' file
    //Returns true or false depending depending on if  the account was added to the file or not
    protected static boolean writeusers(Account obj) {
        try {
            objectOut = new ObjectOutputStream(new FileOutputStream("Users.dat", true)) {
                protected void writeStreamHeader() throws IOException {
                    reset();
                }
            };
            objectOut.writeObject(obj);
            objectOut.flush();
            System.out.println("Object written to file");
            return true;
        } catch (FileNotFoundException ex) {
            System.out.println("Error with specified file");
            ex.printStackTrace();
            return false;
        } catch (IOException ex) {
            System.out.println("Error with I/O processes");
            ex.printStackTrace();
            return false;
        }
    }


    // Function that creates a folder for each user that includes their credit card data .
    protected static void createuserfile(String username) {
        try {
            String path = "" + username;
            fuser = new File(path);
            boolean bool = fuser.mkdir();
            if (bool) {
                System.out.println("Directory created successfully");
            } else {
                System.out.println("Sorry couldn’t create specified directory");
            }
            fileOutuser = new FileOutputStream(path + "\\" + username + ".dat");
            objectOutuser = new ObjectOutputStream(fileOutuser);
        } catch (IOException e) {
            System.out.println("Write error");
        }
    }


    //Function that encrypts the credit card info with AES and it returns the hashed credit card info
    protected static Cards EncryptCard(Cards card, Account user) throws UnsupportedEncodingException {
        card.setCardnumber(AES.encrypt(card.getCardnumber(), new String(user.getSymkey(), "UTF8"), user.getSalt()));
        card.setCardowner(AES.encrypt(card.getCardowner(), new String(user.getSymkey(), "UTF8"), user.getSalt()));
        card.setExpdate(AES.encrypt(card.getExpdate(), new String(user.getSymkey(), "UTF8"), user.getSalt()));
        card.setN_verification(AES.encrypt(card.getN_verification(), new String(user.getSymkey(), "UTF8"), user.getSalt()));
        card.setGroup(AES.encrypt(card.getGroup(), new String(user.getSymkey(), "UTF8"), user.getSalt()));
        return card;
    }


    // Function that decrypts by using AES and returns the encrypted card
    protected static Cards DecryptCard(Cards card, Account user) throws UnsupportedEncodingException {
        card.setCardnumber(AES.decrypt(card.getCardnumber(), new String(user.getSymkey(), "UTF8"), user.getSalt()));
        card.setCardowner(AES.decrypt(card.getCardowner(), new String(user.getSymkey(), "UTF8"), user.getSalt()));
        card.setExpdate(AES.decrypt(card.getExpdate(), new String(user.getSymkey(), "UTF8"), user.getSalt()));
        card.setN_verification(AES.decrypt(card.getN_verification(), new String(user.getSymkey(), "UTF8"), user.getSalt()));
        card.setGroup(AES.decrypt(card.getGroup(), new String(user.getSymkey(), "UTF8"), user.getSalt()));
        return card;
    }


    //Function that writes a card object into the user's file
    //returns true or false depending on if the card was added or not
    protected static boolean createcc(Cards card) {
        try {
            objectOutuser.writeObject(card);
            objectOutuser.flush();
            System.out.println("Credit Card written to file!");
            return true;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return false;

    }


    //Function that creates a salt and a hash by combining salt and the password and it returns the user with the encrypted hash

    //Function that creates Salt and a hash by combining salt+password and returns the encrypter hash
    //Source:
    //https://howtodoinjava.com/security/how-to-generate-secure-password-hash-md5-sha-pbkdf2-bcrypt-examples/
    protected static Account get_SHA_256_SecurePassword(Account user, RSAKeyPairGenerator keyPairGenerator) {
        byte[] salt;
        if (user.getSalt() == null) {
            //generating the salt
            SecureRandom random = new SecureRandom();
            salt = new byte[16];
            random.nextBytes(salt);

            user.setSalt(salt);
        } else {
            salt = user.getSalt();
        }

        // hashing the password by using our new salt
        String generatedPassword = null;
        try {
            MessageDigest msgdig = MessageDigest.getInstance("SHA-256");
            msgdig.update(salt);
            byte[] bytes = msgdig.digest(user.getPassword().getBytes());

            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < bytes.length; i++) {
                builder.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
            }
            generatedPassword = builder.toString();
        } catch (NoSuchAlgorithmException e) {
            System.out.println("There was an error during the password encryption process! ");
            e.printStackTrace();
        }
        user.setHashpw(generatedPassword);
        byte[] secret = execute(generatedPassword, keyPairGenerator);
        user.setSecret(secret);
        return user;
    }

    //Συνάρτηση που παίρνει την σύνοψη και επιστρέφει την κρυπτογραφημένη με το δημόσιο κλειδί
    protected static byte[] execute(String m, RSAKeyPairGenerator keyPairGenerator) {
        try {
            byte[] message = m.getBytes("UTF8");
            byte[] secret = encrypt(keyPairGenerator.getPublicKey(), message);
            return secret;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    //Function that encrypts byte data with a public key
    // Source used :
    //https://stackoverflow.com/questions/24338108/java-encrypt-string-with-existing-public-key-file
    public static byte[] encrypt(PublicKey key, byte[] plaintext) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext);
    }

    // Function that decrypts byte data by using the private key
    //Source used :
    //https://stackoverflow.com/questions/24338108/java-encrypt-string-with-existing-public-key-file
    public static byte[] decrypt(PrivateKey key, byte[] ciphertext) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(ciphertext);
    }

    //Function used during the card deletion from the user's file
    //returns 1 and 0 if the card was or wasnt found
    protected static int deleteCard(JFrame parentframe, String cardNumber, Account user) throws IOException {
        Object obj;
        int found=0;
        try {
            String path = "" + user.getUsername();
            fileInuser = new FileInputStream(path + "\\" + user.getUsername() + ".dat");
            objectInuser = new ObjectInputStream(fileInuser);
            do {
                obj = objectInuser.readObject();
                if (obj instanceof Cards) {
                    String number = AES.decrypt(((Cards) obj).getCardnumber(), new String(user.getSymkey()), user.getSalt());

                    if (!number.equals (cardNumber)) {
                        Lists.cards.add(obj);
                    } else{
                        found=1;
                    }
                }

            } while (obj != null);
            objectInuser.close();
            fileInuser.close();
            objectOutuser.close();
            fileOutuser.close();
        } catch (EOFException e){
            objectInuser.close();
            fileInuser.close();
            objectOutuser.close();
            fileOutuser.close();
            System.out.println("EOFException stin functions delete");
            return found;
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
        return found;
    }

    //Συνάρτηση που χρησημοποιείται για την αναζήτηση καρτών συγκεκριμένου τύπου
    /*protected static void searchCard(JFrame parentframe, String type, Account user, RSAKeyPairGenerator keyPairGenerator)
            throws IOException, ClassNotFoundException {
        Object obj;
        Cards card;
        try {
            String path = "" + user.getUsername();
            fileInuser = new FileInputStream(path + "\\" + user.getUsername() + ".dat");
            objectInuser = new ObjectInputStream(fileInuser);
            do {
                obj = objectInuser.readObject();
                if (obj instanceof Cards) {
                    String group = AES.decrypt(((Cards) obj).getGroup(), new String(user.getSymkey()), user.getSalt());
                    System.out.println(group);
                    if (type.equals(group)) {
                        card = DecryptCard((Cards) obj, user);
                        searchcard.add(card);
                    }
                }
                System.out.println(obj==null);
            } while (obj != null);

            objectInuser.close();
            fileInuser.close();
        } catch (FileNotFoundException ex) {
        } catch (EOFException e){
            objectInuser.close();
            fileInuser.close();
        }
    }*/


    protected static void cardsearch(JFrame parentframe, String type, RSAKeyPairGenerator keyPairGenerator, Account user) throws IOException, ClassNotFoundException {
        Object obj;
        Cards card = new Cards();
        try {
            System.out.println("cardsearch");
            String path = "" + user.getUsername();
            fileInuser = new FileInputStream(path + "\\" + user.getUsername() + ".dat");
            objectInuser = new ObjectInputStream(fileInuser);
            do {
                obj = objectInuser.readObject();
                if (obj instanceof Cards) {
                    String group = AES.decrypt(((Cards) obj).getGroup(), new String(user.getSymkey()), user.getSalt());
                    if (type.equals(group)) {
                        card = DecryptCard((Cards) obj, user);
                        searchcard.add(card);
                    }
                }
            } while (obj != null);
        } catch (FileNotFoundException ex) {
            //Logger.getLogger(Register.class.getName()).log(Level.SEVERE, null, ex);
        }catch (EOFException e){
            Frames.searchFrame(parentframe, searchcard);
            objectInuser.close();
            fileInuser.close();
        }
    }

    // Function that was used to modify a card's info
    protected static Cards modifySearch(String numbercc, RSAKeyPairGenerator keyPairGenerator, Account user) throws IOException, ClassNotFoundException {
        Object obj;
        Cards card = new Cards();
        System.out.println(card.toString());
        try {
            System.out.println("modifySearch");
            String path = "" + user.getUsername();
            fileInuser = new FileInputStream(path + "\\" + user.getUsername() + ".dat");
            objectInuser = new ObjectInputStream(fileInuser);
            do {
                obj = objectInuser.readObject();
                if (obj instanceof Cards) {
                    String number = AES.decrypt(((Cards) obj).getCardnumber(), new String(user.getSymkey()), user.getSalt());
                    if (numbercc.equals(number)) {
                        card = DecryptCard((Cards) obj, user);
                    }else {
                        Lists.modify.add(obj);
                    }
                }
            } while (obj != null);
        } catch (FileNotFoundException ex) {
            //Logger.getLogger(Register.class.getName()).log(Level.SEVERE, null, ex);
        }catch (EOFException e){
            objectInuser.close();
            fileInuser.close();
            objectOutuser.close();
            fileOutuser.close();
            return card;
        }
        card.setCardnumber("");
        return card;
    }

    // Function that shows cards from the user's file .
    protected static void displaycards(RSAKeyPairGenerator keyPairGenerator, Account user) throws IOException, ClassNotFoundException {
        Object obj;
        Cards card;
        try {
            System.out.println("displaycards");
            String path = "" + user.getUsername();
            fileInuser = new FileInputStream(path + "\\" + user.getUsername() + ".dat");
            objectInuser = new ObjectInputStream(fileInuser);
            do {
                obj = objectInuser.readObject();
                if (obj instanceof Cards) {
                    System.out.println("Display obj: " + obj.toString());
                }
            } while (obj != null);
        } catch (FileNotFoundException ex) {
            //Logger.getLogger(Register.class.getName()).log(Level.SEVERE, null, ex);
        } catch (EOFException e){
            objectInuser.close();
            fileInuser.close();
        }
    }

    //Function that is used while checking if a credit card is Συνάρτηση που χρησημοποιείται για τον έλεγχο της ημερομηνίας λήξης μίας κάρτας
    protected static int dateComp(String date1, String date2) {
        String[] todaydate = date1.split("/");
        String[] datecheck2 = date2.split("/");
        if (parseInt(todaydate[1]) != parseInt(datecheck2[1]))//Έλεγχος Χρονιάς
        {
            if (parseInt(todaydate[0]) > parseInt(datecheck2[0]))//Η πρώτη ημερομηνία είναι πιό μετά λόγω μήνα
            {
                return -1;
            } else {//Η δεύτερη ημερομηνία είναι πιο μετά λόγω μήνα
                return 1;
            }
        } else {//Αν είναι ίδια η χρόνια
            if (parseInt(todaydate[0]) <= parseInt(datecheck2[0]))//Αν έχουμε ίδιο μήνα ή είναι πιο μετά ο μήνας της date2
            {
                return 1;
            } else {//Αν είναι πιο μετά ο μήνας της πρώτης ημερομηνίας τότε δεν μπορεί να προχωρήσει
                return -1;
            }
        }
    }
}

