import java.io.Serializable;

//User class
public class Account implements Serializable{
    private String surname;
    private String firstname;
    private String username;
    private String email;
    private String password;
    private byte[] secret;// hash
    private byte[] salt; // Τυχαίο αλφαριθμητικό
    private String hashpw;// Σύνοψη password
    private byte[] symkey;// Συμμετρικό κλειδί του χρήστη

    //Constructors
    protected Account(String surname, String firstname, String email, String username, String password){
        this.surname = surname;
        this.firstname = firstname;
        this.username = username;
        this.email = email;
        this.password = password;
    }

    protected Account(String username, String password){
        this.username = username;
        this.password = password;
        this.surname = null;
        this.firstname = null;
        this.email = null;
    }
    //Accessors
    protected void setSurname(String surname) {
        this.surname = surname;
    }
    protected String getSurname(){
        return surname;
    }

    protected void setFirstname(String firstname) {
        this.firstname = firstname;
    }
    protected String getFirstname(){
        return firstname;
    }

    protected void setUsername(String username) {
        this.username = username;
    }
    protected String getUsername(){
        return username;
    }

    protected void setEmail(String email) {
        this.email = email;
    }
    protected String getEmail(){
        return email;
    }

    protected void setPassword(String password) {
        this.password = password;
    }
    protected String getPassword(){
        return password;
    }

    protected void setSecret(byte[] secret) {
        this.secret = secret;
    }
    protected byte[] getSecret(){
        return secret;
    }

    protected void setSalt(byte[] salt) {
        this.salt = salt;
    }
    protected byte[] getSalt(){
        return salt;
    }

    protected void setHashpw(String hashpw) {
        this.hashpw = hashpw;
    }
    protected String getHashpw(){
        return hashpw;
    }

    protected void setSymkey(byte[] symkey) {
        this.symkey = symkey;
    }
    protected byte[] getSymkey(){
        return symkey;
    }

    public String toString() {
        return "Surname: " + surname + " Firstname: " + firstname + " Username: " + username + " Email: " + email + " Password: " + password + " Hash Password: " + hashpw;
    }
}
