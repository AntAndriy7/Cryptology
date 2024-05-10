import java.math.BigInteger;
import java.security.SecureRandom;

public class RSA {

    private BigInteger mod;
    private BigInteger privateKey;
    private BigInteger publicKey;
    private final int bitLength = 512;

    public RSA() {
        SecureRandom random = new SecureRandom();
        BigInteger p = new BigInteger(bitLength / 2, 100, random);
        BigInteger q = new BigInteger(bitLength / 2, 100, random);

        mod = p.multiply(q);
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

        for (BigInteger i = BigInteger.valueOf(2); i.compareTo(phi) < 0; i = i.add(BigInteger.ONE)) {
            if (i.gcd(phi).equals(BigInteger.ONE)) {
                publicKey = i;
                break;
            }
        }
        privateKey = publicKey.modInverse(phi);
    }

    public BigInteger encrypt(BigInteger message) {
        return message.modPow(publicKey, mod);
    }

    public BigInteger decrypt(BigInteger encryptedMessage) {
        return encryptedMessage.modPow(privateKey, mod);
    }

    public static void main(String[] args) {
        RSA rsa = new RSA();
        String text = "Hello World";
        BigInteger message = new BigInteger(text.getBytes());

        BigInteger encrypted_message = rsa.encrypt(message);
        System.out.println("Шифроване повідомлення: " + encrypted_message);

        BigInteger decrypted_message = rsa.decrypt(encrypted_message);
        System.out.println("Розшифроване повідомлення: " + new String(decrypted_message.toByteArray()));
    }
}
