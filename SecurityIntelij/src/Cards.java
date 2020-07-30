import java.io.Serializable;

//Card class
public class Cards implements Serializable {
    private String cardowner;//Name of Credit Card owner
    private String cardnumber;// 16digit credit card number
    private String expdate;// expiration date
    private String n_verification;// CVV
    private String group;// Credit card group

    //Constructor
    protected Cards(String cardowner, String cardnumber, String expdate, String n_verification, String group) {
        this.cardowner = cardowner;
        this.cardnumber = cardnumber;
        this.expdate = expdate;
        this.n_verification = n_verification;
        this.group = group;
    }

    protected Cards() {
    }

    //Accessors
    protected void setCardowner(String cardowner) {
        this.cardowner = cardowner;
    }

    protected String getCardowner() {
        return this.cardowner;
    }

    protected void setCardnumber(String cardnumber) {
        this.cardnumber = cardnumber;
    }

    protected String getCardnumber() {
        return this.cardnumber;
    }

    protected void setExpdate(String expdate) {
        this.expdate = expdate;
    }

    protected String getExpdate() {
        return this.expdate;
    }

    protected void setN_verification(String n_verification) {
        this.n_verification = n_verification;
    }

    protected String getN_verification() {
        return this.n_verification;
    }

    protected void setGroup(String group) {
        this.group = group;
    }

    protected String getGroup() {
        return this.group;
    }

    public String toString() {
        return "Cardowner: " + this.cardowner + " Cardnumber: " + this.cardnumber + " Expdate: " + this.expdate + " Number of verification: " + this.n_verification + " Group: " + this.group;
    }
}
