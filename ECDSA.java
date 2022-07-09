import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.util.Base64;

public class ECDSA
{
    private ECPrivateKey priv;
    private ECPublicKey pub;

    public ECDSA()
    {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec curve = new ECGenParameterSpec("secp256k1");
            kpg.initialize(curve);
            KeyPair kp = kpg.genKeyPair();
            priv = (ECPrivateKey) kp.getPrivate();
            pub = (ECPublicKey) kp.getPublic();

            BigInteger S = priv.getS();
            ECPoint W = pub.getW();
            BigInteger WX = W.getAffineX();
            BigInteger WY = W.getAffineY();

            
            System.out.println( "Private Key = " + S.toString(16)+"\n");
            System.out.println( "Public Key (X) = " + WX.toString(16)+"\n");
            System.out.println( "Public Key (Y) = " + WY.toString(16)+"\n");
        } 
        
        catch(NoSuchAlgorithmException e) {
            e.printStackTrace();
        } 

        catch(InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }

    private static String bytesToString(byte[] encrypted)
    {
        String test = "";
        for (byte b : encrypted)
        {
            test += Byte.toString(b);
        }
        return test;
    }
 
    // Encrypt message
    public String encrypt(byte[] message)
    {
        try {
        Signature ecdsaSign = Signature.getInstance("SHA256withECDSA");
        ecdsaSign.initSign(priv);
        ecdsaSign.update(message);
        byte[] signature = ecdsaSign.sign();
        String sig = Base64.getEncoder().encodeToString(signature);

        return sig;
        }

        catch(Exception e) {
            e.printStackTrace();
            return "";
        }
    }
 
    // Decrypt message
    public boolean verify(byte[] message, String sig)
    {   
        try {
        Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA");
        
        ecdsaVerify.initVerify(pub);
        ecdsaVerify.update(message);
        
        boolean result = ecdsaVerify.verify(Base64.getDecoder().decode(sig));

        return result;
        } 

        catch(Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public void verifyKeys() {
        System.out.println("Verifying Key Pair");

        String teststring = "test";
        System.out.println("Encrypting String: " + teststring);
        System.out.println("String in Bytes: "+ bytesToString(teststring.getBytes()));
        
        // encrypt
        String sig = encrypt(teststring.getBytes());
        
        System.out.println("Message Signature: " + sig);

        // verify
        boolean res = verify(teststring.getBytes(), sig);
        
        System.out.println("Valid: " + res);
        System.out.println("\n");
    }
 
    public static void main(String[] args) throws Exception
    {
        ECDSA ecd = new ECDSA();
        
        
        ecd.verifyKeys();

        DataInputStream in = new DataInputStream(System.in);
        String teststring;
        System.out.println("Enter the plain text:");
        teststring = in.readLine();
        System.out.println("Encrypting String: " + teststring);
        System.out.println("String in Bytes: "
                + bytesToString(teststring.getBytes()));
        
        // encrypt
        String sig = ecd.encrypt(teststring.getBytes());
        
        System.out.println("Message Signature: " + sig);

        // verify
        boolean res = ecd.verify(teststring.getBytes(), sig);
        
        System.out.println("Valid: " + res);
        System.out.println("\n");
    }
 
    
}
