import javax.crypto.BadPaddingException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.Calendar;
import java.awt.FlowLayout;
import javax.swing.JFrame;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.border.TitledBorder;

public class Frames extends JFrame {
    protected static int year = Calendar.getInstance().get(Calendar.YEAR);
    protected static int month = Calendar.getInstance().get(Calendar.MONTH);

    protected static String[] months = {"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12"};
    protected static String[] years = {"2020", "2021", "2022", "2023", "2024", "2025", "2026", "2027", "2028", "2029", "2030"};


    //Function that has the Frame that were currently in as a parameter to add a menu bar
    protected static JMenuBar menuBars(JFrame frame, RSAKeyPairGenerator keyPairGenerator) {

        JMenuBar mainBar;
        JMenu menu1, user, menu2;
        JMenuItem new_user, login, exit;
        JMenuItem about;

        //Αρχικοποίηση δίνοντας και όνομα στις επιλογές που θα έχει η μπάρα του μενού
        mainBar = new JMenuBar();
        menu1 = new JMenu("File");
        user = new JMenu("User");
        new_user = new JMenuItem("New User");
        login = new JMenuItem("Login");
        exit = new JMenuItem("Exit");

        menu2 = new JMenu("About");
        about = new JMenuItem("Details");

        mainBar.add(menu1);
        mainBar.add(menu2);

        menu1.add(user);
        menu1.add(exit);
        user.add(new_user);
        user.add(login);

        menu2.add(about);

        //Κατά την επιλογή του New User θα εμφανίζει στον χρήστη την φόρμα εγγραφής για να εισάγει τα στοιχεία του
        new_user.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                int n = JOptionPane.showOptionDialog(null, "Do you want to add a new user?", "New User", JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE, null, Lists.options, Lists.options[1]);
                if (n == 0) {
                    frame.dispose();
                    newAccountFrame(keyPairGenerator);
                }
            }
        });

        //Κατά την επιλογή του Login θα εμφανίζει την φόρμα για να εισάγει τα στοιχεία του για να μπει στην πλατφόρμα
        login.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                int n = JOptionPane.showOptionDialog(null, "Do you want to do login?", "Login", JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE, null, Lists.options, Lists.options[1]);
                if (n == 0) {
                    frame.dispose();
                    firstFrame(keyPairGenerator);
                }
            }
        });

        //Κατά την επιλογή του Exit τον ρωτάει αν όντως θέλει να βγεί και κλείνει το πρόγραμμα
        exit.addActionListener(new ActionListener() {//Κουμπί εξόδου και παράθυρο επικήρωσης αυτού
            public void actionPerformed(ActionEvent e) {
                int n = JOptionPane.showOptionDialog(null, "Do you want to exit?", "Exit", JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE, null, Lists.options, Lists.options[1]);
                if (n == 0) System.exit(0);
            }
        });

        //Πληροφορίες με τα στοιχεία
        about.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                JOptionPane.showMessageDialog(null, "University of Aegean\n" +
                        "Information & Communication Systems Security\n" +
                        "Students:\n" +
                        "▪ Theofanis Bakitas 321/2015133\n" +
                        "▪ Georgios Bastounis 321/2015139\n", "About", JOptionPane.INFORMATION_MESSAGE);
            }
        });

        //Επιστροφή της mainbar
        return mainBar;
    }

    //Login window function
    protected static void firstFrame(RSAKeyPairGenerator keyPairGenerator) {
        JFrame first = new JFrame();//Frame Name
        JPanel row1, row2, row3, row4, row5;//row names
        JLabel username, password;
        JTextField username1;//Fields that the user has to insert text into
        JPasswordField password1;
        JButton connect, create, quit;//Buttons that show the user options

        first.setDefaultCloseOperation(EXIT_ON_CLOSE);

        first.setTitle("Program");

        first.setLayout(new FlowLayout());

        first.setJMenuBar(menuBars(first, keyPairGenerator));

        row1 = new JPanel();
        username = new JLabel("Username: ");

        row2 = new JPanel();
        username1 = new JTextField(20);

        row3 = new JPanel();
        password = new JLabel("Password: ");

        row4 = new JPanel();
        password1 = new JPasswordField(20);

        row5 = new JPanel();
        connect = new JButton("Connect");
        create = new JButton("Create New Account");
        quit = new JButton("Exit");

        Container panel = first.getContentPane();
        GridLayout layout = new GridLayout(5, 1);
        panel.setLayout(layout);
        FlowLayout flowlayout = new FlowLayout();

        row1.setLayout(flowlayout);
        row1.add(username);

        row2.setLayout(flowlayout);
        row2.add(username1);

        row3.setLayout(flowlayout);
        row3.add(password);

        row4.setLayout(flowlayout);
        row4.add(password1);

        row5.setLayout(flowlayout);
        row5.add(connect);
        row5.add(create);
        row5.add(quit);
        first.add(row1);
        first.add(row2);
        first.add(row3);
        first.add(row4);
        first.add(row5);

        // login button
        connect.addActionListener(new ActionListener() {//Button that starts the login process
            public void actionPerformed(ActionEvent e) {
                if (username1.getText().equals("")) {
                    JOptionPane.showMessageDialog(first, "Please, Fill the gaps!!!", "Error Message", JOptionPane.ERROR_MESSAGE);
                } else if (username1.getText() != null) {
                    if (new String(password1.getPassword()).equals("")) {
                        JOptionPane.showMessageDialog(first, "Please, Fill the gaps!!!", "Error Message", JOptionPane.ERROR_MESSAGE);
                    } else {
                        Account user = new Account(username1.getText(), new String(password1.getPassword()));
                        try {
                            user = Functions.checkaccount(user, keyPairGenerator); //Checks if the user exists in the user folder and returns the whole user object
                            //If its not null then login was succesfully done otherwise it shows an error
                            if (user != null) {
                                first.dispose();
                                seconcdFrame(keyPairGenerator, user);
                            } else {
                                JOptionPane.showMessageDialog(first, "Invalid Login Credentials!!!", "Error Message", JOptionPane.ERROR_MESSAGE);
                            }
                        } catch (ClassNotFoundException | NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException
                                | IllegalBlockSizeException | BadPaddingException | IOException ex) {
                            ex.printStackTrace();
                        }
                    }
                }
            }
        });

        //Button that creates a new user
        create.addActionListener(new ActionListener() {//Button that  creates a new account
            public void actionPerformed(ActionEvent e) {
                int n = JOptionPane.showOptionDialog(null, "Do you want to Create new account?", "New Account", JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE, null, Lists.options, Lists.options[1]);

                if (n == 0) {
                    first.dispose();
                    newAccountFrame(keyPairGenerator);
                }
            }
        });

        //quit app button
        quit.addActionListener(new ActionListener() {//Exit button which also includes a verification window Κουμπί εξόδου και παράθυρο επικήρωσης αυτού
            public void actionPerformed(ActionEvent e) {
                System.exit(0);
            }
        });

        first.setContentPane(panel);
        first.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        first.setSize(400, 250);
        first.setLocationRelativeTo(null);
        first.setVisible(true);
    }

    //Function that makes a "Create a new Account" Window
    protected static void newAccountFrame(RSAKeyPairGenerator keyPairGenerator) {
        JFrame new_account = new JFrame();//Όνομα Frame
        JPanel row1, row2, row3, row4, row5;//Το όνομα των γραμμών του παραθύρου
        JLabel surname, fisrtname, username, email, password, confirm;
        JTextField surname1, fisrtname1, username1, email1;//Πεδία που εισάγει ο χρήστης στην αναζήτηση
        JPasswordField password1, confirm1;
        JButton create, cancel;//Κουμπιά για τις επιλογές του χρήστη

        new_account.setDefaultCloseOperation(EXIT_ON_CLOSE);

        new_account.setTitle("New Account");

        new_account.setLayout(new FlowLayout());

        new_account.setJMenuBar(menuBars(new_account, keyPairGenerator));

        row1 = new JPanel();
        surname = new JLabel("Surname: ");
        surname1 = new JTextField(20);
        fisrtname = new JLabel("First name: ");
        fisrtname1 = new JTextField(20);

        row2 = new JPanel();
        email = new JLabel("e-Mail: ");
        email1 = new JTextField(20);

        row3 = new JPanel();
        username = new JLabel("Username: ");
        username1 = new JTextField(20);

        row4 = new JPanel();
        password = new JLabel("Password: ");
        password1 = new JPasswordField(20);
        password1.setEchoChar('*');
        confirm = new JLabel("Confirm");
        confirm1 = new JPasswordField(20);
        confirm1.setEchoChar('*');
        row5 = new JPanel();

        create = new JButton("Create New Account");
        cancel = new JButton("Cancel");

        Container panel = new_account.getContentPane();
        GridLayout layout = new GridLayout(5, 2);
        panel.setLayout(layout);
        FlowLayout flowlayout = new FlowLayout();

        row1.setLayout(flowlayout);
        row1.add(surname);
        row1.add(surname1);
        row1.add(fisrtname);
        row1.add(fisrtname1);

        row2.setLayout(flowlayout);
        row2.add(email);
        row2.add(email1);

        row3.setLayout(flowlayout);
        row3.add(username);
        row3.add(username1);

        row4.setLayout(flowlayout);
        row4.add(password);
        row4.add(password1);
        row4.add(confirm);
        row4.add(confirm1);

        row5.setLayout(flowlayout);
        row5.add(create);
        row5.add(cancel);

        new_account.add(row1);
        new_account.add(row2);
        new_account.add(row3);
        new_account.add(row4);
        new_account.add(row5);

        //Κουμπί για την δημιουργία του χρήστη
        create.addActionListener(new ActionListener() {//κουμπί για την εκκίνηση και ανάλογα την πίστα κλήση συναρτήσεων για την εμφανιση της
            public void actionPerformed(ActionEvent e) {
                if (surname1.getText().equals("") || fisrtname1.getText().equals("") || email1.getText().equals("") || username1.getText().equals("") ||
                        new String(password1.getPassword()).equals("") || new String(confirm1.getPassword()).equals("")) {
                    JOptionPane.showMessageDialog(new_account, "Please, Fill the gaps!!!", "Error Message", JOptionPane.ERROR_MESSAGE);
                } else if (surname1.getText() != null && fisrtname1.getText() != null && username1.getText() != null) {
                    if (!email1.getText().matches(Functions.EMAIL_PATTERN)) {
                        JOptionPane.showMessageDialog(new_account, "E-mail already exists!!!", "Email not available", JOptionPane.ERROR_MESSAGE);
                    } else if (new String(password1.getPassword()).equals(new String(confirm1.getPassword()))) {

                        int n = JOptionPane.showOptionDialog(null, "Are you sure about the information you provided?", "Create Account",
                                JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE, null, Lists.options, Lists.options[1]);

                        Account user = new Account(surname1.getText(), fisrtname1.getText(), email1.getText(), username1.getText(), new String(password1.getPassword()));

                        user = Functions.get_SHA_256_SecurePassword(user, keyPairGenerator);//Παραγωγή κρυπτογραημένης σύνοψης, τυχαίου αλφαριθμητικού και σύνοψης
                        try {//Παραγωγή συμμετρικού κλειδιού και κρυπτογράφιση του με το δημόσιο κλείδι
                            SecretKey symkey = AES.keyGenerator();
                            byte[] message = Base64.getEncoder().encodeToString(symkey.getEncoded()).getBytes("UTF8");
                            byte[] secret = Functions.encrypt(keyPairGenerator.getPublicKey(), message);
                            user.setSymkey(secret);
                        } catch (NoSuchAlgorithmException | UnsupportedEncodingException | NoSuchPaddingException
                                | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
                            ex.printStackTrace();
                        }

                        if (n == 0) {
                            //Έλεγχος αν υπάρχει το username στο αρχείο χρηστών
                            if (!Functions.checkusername(user)) {
                                JOptionPane.showMessageDialog(new_account, "Username is not available!!!", "Username not available", JOptionPane.ERROR_MESSAGE);
                                user = null;
                                username1.setText("");
                                password1.setText("");
                                confirm1.setText("");
                            } else {
                                //Αν δεν υπάρχει τότε δημιουργεί έναν φάκελο χρήστη και γράφεται ο χρήστης στο αρχείο χρηστών
                                if (Functions.writeusers(user)) {
                                    Functions.createuserfile(username1.getText());
                                    JOptionPane.showMessageDialog(null, "Your Account has been succesfully created!!!", "Success", JOptionPane.INFORMATION_MESSAGE);
                                    new_account.dispose();
                                    seconcdFrame(keyPairGenerator, user);
                                } else {
                                    JOptionPane.showMessageDialog(new_account, "What is fucking go!!!", "what??", JOptionPane.ERROR_MESSAGE);
                                }
                            }
                        }
                    } else {
                        JOptionPane.showMessageDialog(new_account, "Must contain at least one number and one uppercase and lowercase letter, and at least 8 or more characters", "Error Message", JOptionPane.ERROR_MESSAGE);
                        password1.setText("");
                        confirm1.setText("");
                    }
                }
            }
        });

        //Κουμπί για την ακύρωση της δημιουργίας και επιστροφή στο παράθυρο του login
        cancel.addActionListener(new ActionListener() {//Κουμπί εξόδου και παράθυρο επικήρωσης αυτού
            public void actionPerformed(ActionEvent e) {
                new_account.dispose();
                firstFrame(keyPairGenerator);
            }
        });

        new_account.setContentPane(panel);
        new_account.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        new_account.pack();
        new_account.setLocationRelativeTo(null);
        new_account.setVisible(true);
    }

    //Function that makes an option window that includes the following actions - Search / Add / Delete / Modify / Log out -
    protected static void seconcdFrame(RSAKeyPairGenerator keyPairGenerator, Account user) {
        JFrame second = new JFrame();//Όνομα Frame
        JPanel row1, row2, row3, row4;//Το όνομα των γραμμών του παραθύρου
        JLabel info;
        JButton search, add, delete, modify, logout;//Κουμπιά για τις επιλογές του χρήστη

        second.setDefaultCloseOperation(EXIT_ON_CLOSE);

        second.setTitle("Add credit card information");

        second.setLayout(new FlowLayout());

        row1 = new JPanel();
        info = new JLabel("Options");

        row2 = new JPanel();
        search = new JButton("Search Credit Card");
        add = new JButton("Add Credit Card");

        row3 = new JPanel();
        delete = new JButton("Delete Credit Card");
        modify = new JButton("Modify Credit Card");

        row4 = new JPanel();
        logout = new JButton("Logout");

        Container panel = second.getContentPane();
        GridLayout layout = new GridLayout(4, 2);
        panel.setLayout(layout);
        FlowLayout flowlayout = new FlowLayout();

        row1.setLayout(flowlayout);
        row1.add(info);

        row2.setLayout(flowlayout);
        row2.add(search);
        row2.add(add);

        row3.setLayout(flowlayout);
        row3.add(delete);
        row3.add(modify);

        row4.setLayout(flowlayout);
        row4.add(logout);

        second.add(row1);
        second.add(row2);
        second.add(row3);
        second.add(row4);

        //Κουμπί για την αναζήτηση καρτών
        search.addActionListener(new ActionListener() {//κουμπί για την εκκίνηση και ανάλογα την πίστα κλήση συναρτήσεων για την εμφανιση της
            public void actionPerformed(ActionEvent e) {
                second.dispose();
                typesearchFrame(keyPairGenerator, user);
            }
        });

        //Κουμπί για να προσθέσω νέα κάρτα
        add.addActionListener(new ActionListener() {//Κουμπί εξόδου και παράθυρο επικήρωσης αυτού
            public void actionPerformed(ActionEvent e) {
                second.dispose();
                cardsFrame(keyPairGenerator, user);
            }
        });

        //Κουμπί για την διαγραφή κάρτας
        delete.addActionListener(new ActionListener() {//Κουμπί εξόδου και παράθυρο επικήρωσης αυτού
            public void actionPerformed(ActionEvent e) {
                second.dispose();
                deleteFrame(keyPairGenerator, user);
            }
        });

        //Κουμπί για την τροποποίηση κάρτας
        modify.addActionListener(new ActionListener() {//Κουμπί εξόδου και παράθυρο επικήρωσης αυτού
            public void actionPerformed(ActionEvent e) {
                second.dispose();
                modifyFrame(keyPairGenerator, user);
            }
        });

        //Κουμπί για την έξοδο από τον χρήστη
        logout.addActionListener(new ActionListener() {//Κουμπί εξόδου και παράθυρο επικήρωσης αυτού
            public void actionPerformed(ActionEvent e) {
                second.dispose();
                firstFrame(keyPairGenerator);
            }
        });

        second.setContentPane(panel);
        second.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        second.pack();
        second.setLocationRelativeTo(null);
        second.setVisible(true);
    }

    //Function with  card type option menu
    protected static void typesearchFrame(RSAKeyPairGenerator keyPairGenerator, Account user) {
        JFrame typesearch = new JFrame();//Όνομα Frame
        JPanel row1, row2, row3;//Το όνομα των γραμμών του παραθύρου
        JLabel info;
        JButton search, cancel;//Κουμπιά για τις επιλογές του χρήστη

        ButtonGroup sgroup;////Group με τις επιλογές των check κουμπιών ώστε να μπορώ να ξεχωρίσω την επιλογή της κάρτας

        JRadioButton visa, mastercard, american, diners;//Τα check κουμπιά που θα έχω στον χρήστη

        typesearch.setDefaultCloseOperation(EXIT_ON_CLOSE);

        typesearch.setTitle("Search Card");

        typesearch.setLayout(new FlowLayout());

        row1 = new JPanel();
        info = new JLabel("Search credit card");

        row2 = new JPanel();
        visa = new JRadioButton("Visa");
        visa.setMnemonic(KeyEvent.VK_B);
        visa.setActionCommand("Visa");
        visa.setSelected(true);

        mastercard = new JRadioButton("Master Card");
        mastercard.setMnemonic(KeyEvent.VK_C);
        mastercard.setActionCommand("Master Card");

        american = new JRadioButton("American");
        american.setMnemonic(KeyEvent.VK_D);
        american.setActionCommand("American");

        diners = new JRadioButton("Diners");
        diners.setMnemonic(KeyEvent.VK_E);
        diners.setActionCommand("Diners");

        sgroup = new ButtonGroup();
        sgroup.add(visa);
        sgroup.add(mastercard);
        sgroup.add(american);
        sgroup.add(diners);

        row3 = new JPanel();
        search = new JButton("Search Credit Card");
        cancel = new JButton("Cancel");

        Container panel = typesearch.getContentPane();
        GridLayout layout = new GridLayout(3, 2);
        panel.setLayout(layout);
        FlowLayout flowlayout = new FlowLayout();

        row1.setLayout(flowlayout);
        row1.add(info);

        row2.setLayout(flowlayout);
        row2.add(visa);
        row2.add(mastercard);
        row2.add(american);
        row2.add(diners);

        row3.setLayout(flowlayout);
        row3.add(search);
        row3.add(cancel);

        typesearch.add(row1);
        typesearch.add(row2);
        typesearch.add(row3);

        //Κουμπί για την αναζήτηση κάρτας
        search.addActionListener(new ActionListener() {//κουμπί για την εκκίνηση και ανάλογα την πίστα κλήση συναρτήσεων για την εμφανιση της
            public void actionPerformed(ActionEvent e) {
                //Αναλόγως την επιλογή του τύπου της κάρτας που θέλει να αναζητήσει ο χρήστης καλείται η ανάλογη συνάρτηση
                if (visa.isSelected()) {
                    try {
                        Functions.cardsearch(typesearch,"Visa", keyPairGenerator, user);
                    } catch (IOException | ClassNotFoundException ex) {
                        ex.printStackTrace();
                    }
                } else if (mastercard.isSelected()) {
                    try {
                        Functions.cardsearch(typesearch,"Master Card", keyPairGenerator, user);
                    } catch (IOException | ClassNotFoundException ex) {
                        ex.printStackTrace();
                    }
                } else if (american.isSelected()) {
                    try {
                        Functions.cardsearch(typesearch,"American", keyPairGenerator, user);
                    } catch (IOException | ClassNotFoundException ex) {
                        ex.printStackTrace();
                    }
                } else if (diners.isSelected()) {
                    try {
                        Functions.cardsearch(typesearch,"Diners", keyPairGenerator, user);
                    } catch (IOException | ClassNotFoundException ex) {
                        ex.printStackTrace();
                    }
                }
            }
        });

        //Κουμπί επαναφοράς στο παράθυρο επιλογών του χρήστη
        cancel.addActionListener(new ActionListener() {//Κουμπί εξόδου και παράθυρο επικήρωσης αυτού
            public void actionPerformed(ActionEvent e) {
                typesearch.dispose();
                seconcdFrame(keyPairGenerator, user);
            }
        });

        typesearch.setContentPane(panel);
        typesearch.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        typesearch.pack();
        typesearch.setLocationRelativeTo(null);
        typesearch.setVisible(true);
    }

    //Add a new card menu
    protected static void cardsFrame(RSAKeyPairGenerator keyPairGenerator, Account user) {

        JFrame cards = new JFrame();// Frame Name
        JPanel row1, row2, row3, row4, row5, row6, row7;
        JLabel info, cardowner, cardnumber, expdate, n_verification;
        JTextField cardowner1, cardnumber1, expdate1, n_verification1;
        JButton create, cancel;// user option buttons

        JComboBox monthlist = new JComboBox(months);
        JComboBox yearlist = new JComboBox(years);

        ButtonGroup sgroup;////Group option

        JRadioButton visa, mastercard, american, diners;

        cards.setDefaultCloseOperation(EXIT_ON_CLOSE);

        cards.setTitle("Add credit card information");
        cards.setLayout(new FlowLayout());

        row1 = new JPanel();
        info = new JLabel("Add credit card information");

        row2 = new JPanel();
        visa = new JRadioButton("Visa");
        visa.setMnemonic(KeyEvent.VK_B);
        visa.setActionCommand("Name");
        visa.setSelected(true);

        mastercard = new JRadioButton("Master Card");
        mastercard.setMnemonic(KeyEvent.VK_C);
        mastercard.setActionCommand("Master Card");

        american = new JRadioButton("American");
        american.setMnemonic(KeyEvent.VK_D);
        american.setActionCommand("American");

        diners = new JRadioButton("Diners");
        diners.setMnemonic(KeyEvent.VK_E);
        diners.setActionCommand("Dinersn");

        sgroup = new ButtonGroup();
        sgroup.add(visa);
        sgroup.add(mastercard);
        sgroup.add(american);
        sgroup.add(diners);

        row3 = new JPanel();
        cardowner = new JLabel("Credit card owner: ");
        cardowner1 = new JTextField(20);

        row4 = new JPanel();
        cardnumber = new JLabel("Credit card number");
        cardnumber1 = new JTextField(16);

        row5 = new JPanel();
        n_verification = new JLabel("Verification number: ");
        n_verification1 = new JTextField(20);

        row6 = new JPanel();
        expdate = new JLabel("Expiration date: ");
        expdate1 = new JTextField(20);

        row7 = new JPanel();
        create = new JButton("Add Credit Card");
        cancel = new JButton("Cancel");

        Container panel = cards.getContentPane();
        GridLayout layout = new GridLayout(7, 2);
        panel.setLayout(layout);
        FlowLayout flowlayout = new FlowLayout();

        row1.setLayout(flowlayout);
        row1.add(info);

        row2.setLayout(flowlayout);
        row2.add(visa);
        row2.add(mastercard);
        row2.add(american);
        row2.add(diners);

        row3.setLayout(flowlayout);
        row3.add(cardowner);
        row3.add(cardowner1);

        row4.setLayout(flowlayout);
        row4.add(cardnumber);
        row4.add(cardnumber1);

        row5.setLayout(flowlayout);
        row5.add(n_verification);
        row5.add(n_verification1);

        row6.setLayout(flowlayout);
        row6.add(expdate);
        row6.add(monthlist);
        row6.add(yearlist);

        row7.setLayout(flowlayout);
        row7.add(create);
        row7.add(cancel);

        cards.add(row1);
        cards.add(row2);
        cards.add(row3);
        cards.add(row4);
        cards.add(row5);
        cards.add(row6);
        cards.add(row7);

        //Credit card creation button
        create.addActionListener(new ActionListener() {//
            public void actionPerformed(ActionEvent e) {
                //Checking the expiration date
                expdate1.setText(months[monthlist.getSelectedIndex()] + "/" + years[yearlist.getSelectedIndex()]);

                String todaydate = (month+1) +"/" + year;

                if (cardowner1.getText().equals("") || cardnumber1.getText().equals("") || n_verification1.getText().equals("")) {
                    JOptionPane.showMessageDialog(cards, "Please, Fill the blanks!!!", "Error Message", JOptionPane.ERROR_MESSAGE);
                } else {
                    try {
                        if (cardnumber1.getText().matches(Functions.CC_PATTERN)) {//CC number pattern checking
                            if (n_verification1.getText().matches(Functions.CVV_PATTERN)) {// pattern for the CVV
                                if (Functions.dateComp(todaydate,expdate1.getText())==1) {//expiration date
                                    //depending on the type of the card
                                    if (visa.isSelected()) {
                                        //creating credit card object
                                        Cards card = new Cards(cardowner1.getText(), cardnumber1.getText(), expdate1.getText(), n_verification1.getText(), "Visa");
                                        //Κρυπτογράφηση στοιχείων κάρτας
                                        card = Functions.EncryptCard(card, user);
                                        //Checking if the card was written to the file
                                        if (Functions.createcc(card)) {
                                            JOptionPane.showMessageDialog(null, "Your credit card has been succesfully created!!!", "Success", JOptionPane.INFORMATION_MESSAGE);
                                            cardowner1.setText("");
                                            cardnumber1.setText("");
                                            expdate1.setText("");
                                            n_verification1.setText("");
                                        } else {
                                            JOptionPane.showMessageDialog(null, "Something Went Wrong!", "Failure", JOptionPane.INFORMATION_MESSAGE);
                                        }
                                    } else if (mastercard.isSelected()) {

                                        Cards card = new Cards(cardowner1.getText(), cardnumber1.getText(), expdate1.getText(), n_verification1.getText(), "Master Card");

                                        card = Functions.EncryptCard(card, user);

                                        if (Functions.createcc(card)) {
                                            JOptionPane.showMessageDialog(null, "Your credit card has been succesfully created!!!", "Success", JOptionPane.INFORMATION_MESSAGE);
                                            cardowner1.setText("");
                                            cardnumber1.setText("");
                                            expdate1.setText("");
                                            n_verification1.setText("");
                                        } else {
                                            JOptionPane.showMessageDialog(null, "Something Went Wrong!", "Failure", JOptionPane.INFORMATION_MESSAGE);
                                        }

                                    } else if (american.isSelected()) {

                                        Cards card = new Cards(cardowner1.getText(), cardnumber1.getText(), expdate1.getText(), n_verification1.getText(), "American");

                                        card = Functions.EncryptCard(card, user);

                                        if (Functions.createcc(card)) {
                                            Functions.displaycards(keyPairGenerator,user);
                                            JOptionPane.showMessageDialog(null, "Your credit card has been succesfully created!!!", "Success", JOptionPane.INFORMATION_MESSAGE);
                                            cardowner1.setText("");
                                            cardnumber1.setText("");
                                            expdate1.setText("");
                                            n_verification1.setText("");
                                        } else {
                                            JOptionPane.showMessageDialog(null, "Something Went Wrong!", "Failure", JOptionPane.INFORMATION_MESSAGE);
                                        }
                                    } else if (diners.isSelected()) {

                                        Cards card = new Cards(cardowner1.getText(), cardnumber1.getText(), expdate1.getText(), n_verification1.getText(), "Diners");

                                        card = Functions.EncryptCard(card, user);

                                        if (Functions.createcc(card)) {
                                            Functions.displaycards(keyPairGenerator,user);
                                            JOptionPane.showMessageDialog(null, "Your credit card has been succesfully created!!!", "Success", JOptionPane.INFORMATION_MESSAGE);
                                            cardowner1.setText("");
                                            cardnumber1.setText("");
                                            expdate1.setText("");
                                            n_verification1.setText("");
                                        } else {
                                            JOptionPane.showMessageDialog(null, "Something Went Wrong!", "Failure", JOptionPane.INFORMATION_MESSAGE);
                                        }

                                    }

                                }else {
                                    JOptionPane.showMessageDialog(cards, "Please, Check your Expiration Date!!!", "Error Message", JOptionPane.ERROR_MESSAGE);
                                }
                            } else {
                                JOptionPane.showMessageDialog(cards, "Please, Check your Number Verification!!!", "Error Message", JOptionPane.ERROR_MESSAGE);
                            }
                        } else {
                            JOptionPane.showMessageDialog(cards, "Enter only numeric digits(0-9) and 16 numbers", "Error Message", JOptionPane.ERROR_MESSAGE);
                            cardnumber1.setText("");
                        }
                    } catch (IOException | ClassNotFoundException ex) {
                        ex.printStackTrace();
                    }
                }
            }
        });


        cancel.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                cards.dispose();
                seconcdFrame(keyPairGenerator, user);
            }
        });

        cards.setContentPane(panel);
        cards.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        cards.pack();
        cards.setLocationRelativeTo(null);
        cards.setVisible(true);
    }


    //Function that shows the elements the user searched for
    protected static void searchFrame(JFrame parentframe, ArrayList<Cards> searchcard) {
        parentframe.setEnabled(false);

        JFrame search = new JFrame();
        JPanel panel = new JPanel();
        JButton ok;
        String[][] rec = new String[searchcard.size()][5];
        panel.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(), "Results", TitledBorder.CENTER, TitledBorder.TOP));

        // Filling a window with the cards we found that match the criteria aka the ones in the searchcard list
        for (int i = 0; i < searchcard.size(); i++) {
            for (int j = 0; j < 5; j++) {
                if (j == 0) {
                    rec[i][j] = searchcard.get(i).getGroup();
                } else if (j == 1) {
                    rec[i][j] = searchcard.get(i).getCardowner();
                } else if (j == 2) {
                    rec[i][j] = searchcard.get(i).getCardnumber();
                } else if (j == 3) {
                    rec[i][j] = searchcard.get(i).getExpdate();
                } else {
                    rec[i][j] = searchcard.get(i).getN_verification();
                }
            }
        }

        String[] header = {"Group", "Owner", "Card Number", "Expiration Date", "Number Verification"};
        JTable table = new JTable(rec, header);
        panel.add(new JScrollPane(table));
        search.add(panel);

        ok = new JButton("OK");
        panel.add(ok);
        search.add(panel);

        //back to the  parentframe
        ok.addActionListener(new ActionListener() {//back button
            public void actionPerformed(ActionEvent e) {
                Functions.searchcard.clear();
                search.dispose();
                parentframe.setEnabled(true);
                parentframe.setVisible(true);
            }
        });

        search.setSize(550, 400);
        search.setVisible(true);
        search.setLocationRelativeTo(null);
        search.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    }

    //Συνάρτηση που μας εμφανίζει το παράθυρο για την διαγραφεί μίας κάρτας
    //function that creates a window for deleting a credit card
    protected static void deleteFrame(RSAKeyPairGenerator keyPairGenerator, Account user) {
        JFrame deleteframe = new JFrame();

        JLabel info;
        JButton delete, cancel;
        JTextField cc_num;
        JLabel cc_num_l;


        info = new JLabel("Fill in the Credit Card information", JLabel.CENTER);
        info.setFont(new Font("Arial", Font.BOLD, 20));
        deleteframe.add(info);
        cc_num=new JTextField();
        cc_num_l= new JLabel("Credit Card Number");

        deleteframe.setDefaultCloseOperation(EXIT_ON_CLOSE);

        deleteframe.setTitle("Fill in the credit card information");

        deleteframe.setLayout(new FlowLayout());

        deleteframe.add(cc_num_l);
        deleteframe.add(cc_num);


        delete = new JButton("Delete Credit Card");
        cancel = new JButton("Cancel");

        deleteframe.add(delete);
        deleteframe.add(cancel);

        Container panel = deleteframe.getContentPane();
        GridLayout layout = new GridLayout(5, 2);
        panel.setLayout(layout);

        delete.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                try {

                    // Trying to delete the card . Returns 0 or 1 depending on if the card was found or not
                    int found = Functions.deleteCard(deleteframe, cc_num.getText(), user);

                    String path = "" + user.getUsername();
                    File file = new File(path + "\\" + user.getUsername() + ".dat");
                    //recreating the file
                    if(file.delete()) {
                        Functions.createuserfile(user.getUsername());
                    }
                    //Δημιουργία καινούργιου αρχείου που περνάει τις κάρτες από την λίστα που τις έχουμε αποθηκεύσει (cards)
                    //creating a new file that contains the remaining cards
                    if(found==0){
                        for(int i=0; i<Lists.cards.size(); i++) {
                            boolean check = false;
                            do{
                                check = Functions.createcc((Cards)Lists.cards.get(i));
                            }while(!check);
                        }
                        JOptionPane.showMessageDialog(null, "Card with such information was not found!!!", "Not Found", JOptionPane.INFORMATION_MESSAGE);
                    }
                    else if(found == 1){
                        for(int i=0; i<Lists.cards.size(); i++) {
                            boolean check = false;
                            do{
                                check = Functions.createcc((Cards)Lists.cards.get(i));
                            }while(!check);
                        }
                        JOptionPane.showMessageDialog(null, "The card was successfully deleted!!!", "Delete", JOptionPane.INFORMATION_MESSAGE);
                    }
                    Lists.cards.clear();
                    deleteframe.dispose();
                    seconcdFrame(keyPairGenerator, user);
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
            }
        });


        cancel.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                deleteframe.dispose();
                seconcdFrame(keyPairGenerator, user);
            }
        });

        deleteframe.setContentPane(panel);
        deleteframe.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        deleteframe.pack();
        deleteframe.setLocationRelativeTo(null);
        deleteframe.setVisible(true);
    }


    // modify a card panel
    protected static void modifyFrame(RSAKeyPairGenerator keyPairGenerator, Account user) {

        JFrame modframe = new JFrame();
        JLabel info;
        JButton modify, cancel;
        JTextField cc_num;
        JLabel cc_num_l;

        info = new JLabel("Fill in the Credit Card information", JLabel.CENTER);
        info.setFont(new Font("Arial", Font.BOLD, 20));
        modframe.add(info);
        cc_num=new JTextField();
        cc_num_l= new JLabel("Credit Card Number :", JLabel.CENTER);

        modframe.setDefaultCloseOperation(EXIT_ON_CLOSE);

        modframe.setTitle("Fill in the credit card information");

        modframe.setLayout(new FlowLayout());

        modframe.add(cc_num_l);
        modframe.add(cc_num);

        modify = new JButton("Modify Credit Card");
        cancel = new JButton("Cancel");

        modframe.add(modify);
        modframe.add(cancel);

        Container panel = modframe.getContentPane();
        GridLayout layout = new GridLayout(5, 2);
        panel.setLayout(layout);


        modify.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                try {

                    Cards card = Functions.modifySearch(cc_num.getText(), keyPairGenerator, user);
                    System.out.println(card.getCardnumber().equals(""));

                    if(card.getCardnumber().equals("")){
                        JOptionPane.showMessageDialog(modframe, "No such card was found!", "Error Message", JOptionPane.ERROR_MESSAGE);
                    } else{
                        modifyFrame2(card, keyPairGenerator, user);
                        modframe.dispose();
                    }
                } catch (IOException | ClassNotFoundException ex) {
                    ex.printStackTrace();
                }

            }
        });


        cancel.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                modframe.dispose();
                seconcdFrame(keyPairGenerator, user);
            }
        });

        modframe.setContentPane(panel);
        modframe.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        modframe.pack();
        modframe.setLocationRelativeTo(null);
        modframe.setVisible(true);
    }

    // Function that creates a modification window info for the new card info
    protected static void modifyFrame2(Cards karta, RSAKeyPairGenerator keyPairGenerator, Account user) {

        JFrame modframe2 = new JFrame();
        JPanel row1, row2, row3, row4, row5, row6, row7;
        JLabel info, cardowner, cardnumber, expdate, n_verification;
        JTextField cardowner1, cardnumber1, expdate1, n_verification1;
        JButton modify, cancel;

        JComboBox monthlist = new JComboBox(months);
        JComboBox yearlist = new JComboBox(years);

        ButtonGroup sgroup;

        JRadioButton visa, mastercard, american, diners;

        modframe2.setDefaultCloseOperation(EXIT_ON_CLOSE);

        modframe2.setTitle("Modify a Card");
        modframe2.setLayout(new FlowLayout());

        row1 = new JPanel();
        info = new JLabel("Edit any information you want to change",JLabel.CENTER);

        row2 = new JPanel();
        visa = new JRadioButton("Visa");
        visa.setMnemonic(KeyEvent.VK_B);
        visa.setActionCommand("Name");
        visa.setSelected(true);

        mastercard = new JRadioButton("Master Card");
        mastercard.setMnemonic(KeyEvent.VK_C);
        mastercard.setActionCommand("Master Card");

        american = new JRadioButton("American");
        american.setMnemonic(KeyEvent.VK_D);
        american.setActionCommand("American");

        diners = new JRadioButton("Diners");
        diners.setMnemonic(KeyEvent.VK_E);
        diners.setActionCommand("Dinersn");

        sgroup = new ButtonGroup();
        sgroup.add(visa);
        sgroup.add(mastercard);
        sgroup.add(american);
        sgroup.add(diners);

        row3 = new JPanel();
        cardowner = new JLabel("Credit card owner: ");
        cardowner1 = new JTextField(20);

        row4 = new JPanel();
        cardnumber = new JLabel("Credit card number");
        cardnumber1 = new JTextField(16);

        row5 = new JPanel();
        n_verification = new JLabel("Verification number: ");
        n_verification1 = new JTextField(20);

        row6 = new JPanel();
        expdate = new JLabel("Expiration date: ");
        expdate1 = new JTextField(20);

        row7 = new JPanel();
        modify = new JButton("Apply Changes");
        cancel = new JButton("Cancel");

        Container panel = modframe2.getContentPane();
        GridLayout layout = new GridLayout(7, 2);
        panel.setLayout(layout);
        FlowLayout flowlayout = new FlowLayout();

        row1.setLayout(flowlayout);
        row1.add(info);

        row2.setLayout(flowlayout);
        row2.add(visa);
        row2.add(mastercard);
        row2.add(american);
        row2.add(diners);

        row3.setLayout(flowlayout);
        row3.add(cardowner);
        row3.add(cardowner1);

        row4.setLayout(flowlayout);
        row4.add(cardnumber);
        row4.add(cardnumber1);

        row5.setLayout(flowlayout);
        row5.add(n_verification);
        row5.add(n_verification1);

        row6.setLayout(flowlayout);
        row6.add(expdate);
        row6.add(monthlist);
        row6.add(yearlist);

        row7.setLayout(flowlayout);
        row7.add(modify);
        row7.add(cancel);

        modframe2.add(row1);
        modframe2.add(row2);
        modframe2.add(row3);
        modframe2.add(row4);
        modframe2.add(row5);
        modframe2.add(row6);
        modframe2.add(row7);


        cardowner1.setText(karta.getCardowner());
        cardnumber1.setText(karta.getCardnumber());
        String[] datecheck2 = karta.getExpdate().split("/");
        monthlist.setSelectedIndex(Integer.parseInt(datecheck2[0])-1);
        yearlist.setSelectedIndex(Integer.parseInt(datecheck2[1])-2020);
        n_verification1.setText(karta.getN_verification());
        if (karta.getGroup().equals("Visa")){
            visa.setSelected(true);
        }
        if (karta.getGroup().equals("Master Card")){
            mastercard.setSelected(true);
        }
        if (karta.getGroup().equals("American")){
            american.setSelected(true);
        }
        if (karta.getGroup().equals("Diners")){
            diners.setSelected(true);
        }

        modify.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                expdate1.setText(months[monthlist.getSelectedIndex()] + "/" + years[yearlist.getSelectedIndex()]);
                String todaydate = (month+1) +"/" + year;

                if (cardowner1.getText().equals("") || cardnumber1.getText().equals("") || n_verification1.getText().equals("")) {
                    JOptionPane.showMessageDialog(modframe2, "Please, Fill the blanks!!!", "Error Message", JOptionPane.ERROR_MESSAGE);
                } else {
                    try {
                        if (cardnumber1.getText().matches(Functions.CC_PATTERN)) {
                            if (n_verification1.getText().matches(Functions.CVV_PATTERN)) {
                                if (Functions.dateComp(todaydate,expdate1.getText())==1) {
                                    String path = "" + user.getUsername();
                                    File file = new File(path + "\\" + user.getUsername() + ".dat");
                                    //deletes the already existing file
                                    if(file.delete()) {
                                        Functions.createuserfile(user.getUsername());
                                    }
                                    if (visa.isSelected()) {
                                        //new modified card
                                        Cards card = new Cards(cardowner1.getText(), cardnumber1.getText(), expdate1.getText(), n_verification1.getText(), "Visa");
                                        //encryption
                                        card = Functions.EncryptCard(card, user);
                                        //adding the card to the list
                                        Lists.modify.add(card);
                                        //recreating the file with the remaining cards /modified cards
                                        for(int i=0; i<Lists.modify.size(); i++){
                                            boolean check=false;
                                            do {
                                                check = Functions.createcc((Cards) Lists.modify.get(i));
                                                System.out.println(check);
                                            }while(!check);
                                        }
                                        Lists.modify.clear();
                                        JOptionPane.showMessageDialog(null, "Your credit card has been succesfully created!!!", "Success", JOptionPane.INFORMATION_MESSAGE);
                                        modframe2.dispose();
                                        seconcdFrame(keyPairGenerator, user);
                                    } else if (mastercard.isSelected()) {
                                        //creating a modified object
                                        Cards card = new Cards(cardowner1.getText(), cardnumber1.getText(), expdate1.getText(), n_verification1.getText(), "Master Card");
                                        //encrypting a modified object
                                        card = Functions.EncryptCard(card, user);
                                        //inserting in the modified list
                                        Lists.modify.add(card);

                                        for(int i=0; i<Lists.modify.size(); i++){
                                            boolean check=false;
                                            do {
                                                check = Functions.createcc((Cards) Lists.modify.get(i));
                                                System.out.println(check);
                                            }while(!check);
                                        }
                                        Lists.modify.clear();
                                        JOptionPane.showMessageDialog(null, "Your credit card has been succesfully created!!!", "Success", JOptionPane.INFORMATION_MESSAGE);
                                        modframe2.dispose();
                                        seconcdFrame(keyPairGenerator, user);

                                    } else if (american.isSelected()) {

                                        Cards card = new Cards(cardowner1.getText(), cardnumber1.getText(), expdate1.getText(), n_verification1.getText(), "American");

                                        card = Functions.EncryptCard(card, user);

                                        Lists.modify.add(card);

                                        for(int i=0; i<Lists.modify.size(); i++){
                                            boolean check=false;
                                            do {
                                                check = Functions.createcc((Cards) Lists.modify.get(i));
                                                System.out.println(check);
                                            }while(!check);
                                        }
                                        Lists.modify.clear();
                                        JOptionPane.showMessageDialog(null, "Your credit card has been succesfully created!!!", "Success", JOptionPane.INFORMATION_MESSAGE);
                                        modframe2.dispose();
                                        seconcdFrame(keyPairGenerator, user);
                                    } else if (diners.isSelected()) {

                                        Cards card = new Cards(cardowner1.getText(), cardnumber1.getText(), expdate1.getText(), n_verification1.getText(), "Diners");

                                        card = Functions.EncryptCard(card, user);

                                        Lists.modify.add(card);

                                        for(int i=0; i<Lists.modify.size(); i++){
                                            boolean check=false;
                                            do {
                                                check = Functions.createcc((Cards) Lists.modify.get(i));
                                                System.out.println(check);
                                            }while(!check);
                                        }
                                        Lists.modify.clear();
                                        JOptionPane.showMessageDialog(null, "Your credit card has been succesfully created!!!", "Success", JOptionPane.INFORMATION_MESSAGE);
                                        modframe2.dispose();
                                        seconcdFrame(keyPairGenerator, user);

                                    }

                                }else {
                                    JOptionPane.showMessageDialog(modframe2, "Please, Check your Expiration Date!!! 756", "Error Message", JOptionPane.ERROR_MESSAGE);
                                }
                            } else {
                                JOptionPane.showMessageDialog(modframe2, "Please, Check your Number Verification!!! 758", "Error Message", JOptionPane.ERROR_MESSAGE);
                            }
                        } else {
                            JOptionPane.showMessageDialog(modframe2, "Enter only numeric digits(0-9) and 16 numbers", "Error Message", JOptionPane.ERROR_MESSAGE);
                            cardnumber1.setText("");
                        }
                    } catch (UnsupportedEncodingException ex) {
                        ex.printStackTrace();
                    }
                }
            }
        });

        //Κουμπί επαναφοράς στο παράθυρο επιλογών του χρήστη
        cancel.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {

                try {
                    String path = "" + user.getUsername();
                    File file = new File(path + "\\" + user.getUsername() + ".dat");

                    if(file.delete()) {
                        Functions.createuserfile(user.getUsername());
                    }

                    Cards card = new Cards(karta.getCardowner(), karta.getCardnumber(), karta.getExpdate(), karta.getN_verification(), karta.getGroup());

                    card = Functions.EncryptCard(card, user);

                    Lists.modify.add(card);

                    for(int i=0; i<Lists.modify.size(); i++){
                        boolean check=false;
                        do {
                            check = Functions.createcc((Cards) Lists.modify.get(i));
                        }while(check==true);
                    }
                    Lists.modify.clear();
                    modframe2.dispose();
                    seconcdFrame(keyPairGenerator, user);
                } catch (UnsupportedEncodingException ex) {
                    ex.printStackTrace();
                }
            }
        });
        modframe2.setContentPane(panel);
        modframe2.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        modframe2.pack();
        modframe2.setLocationRelativeTo(null);
        modframe2.setVisible(true);

    }
}