import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;

public class PasswordGenerator {

    private static final String ALGORITHM = "AES";
    private static final String CHARACTERS_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String CHARACTERS_LOWER = "abcdefghijklmnopqrstuvwxyz";
    private static final String CHARACTERS_DIGITS = "0123456789";
    private static final String CHARACTERS_SYMBOLS = "!@#$%^&*()_+[]{}|;:,.<>?";

    public static String generateComplexPassword(int length, boolean useUppercase, boolean useLowercase,
            boolean useDigits, boolean useSymbols) {
        StringBuilder characters = new StringBuilder();
        if (useUppercase)
            characters.append(CHARACTERS_UPPER);
        if (useLowercase)
            characters.append(CHARACTERS_LOWER);
        if (useDigits)
            characters.append(CHARACTERS_DIGITS);
        if (useSymbols)
            characters.append(CHARACTERS_SYMBOLS);

        if (characters.length() == 0)
            throw new IllegalArgumentException("At least one character set must be selected.");

        SecureRandom random = new SecureRandom();
        StringBuilder password = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            int index = random.nextInt(characters.length());
            password.append(characters.charAt(index));
        }
        return password.toString();
    }

    public static SecretKey generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
        keyGen.init(128); // For AES-128
        return keyGen.generateKey();
    }

    public static String encrypt(String password, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(password.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decrypt(String encryptedPassword, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedPassword);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes);
    }

    public static String assessPasswordStrength(String password) {
        int lengthScore = password.length() > 12 ? 3 : (password.length() > 8 ? 2 : 1);
        int upperScore = password.chars().anyMatch(Character::isUpperCase) ? 2 : 0;
        int lowerScore = password.chars().anyMatch(Character::isLowerCase) ? 2 : 0;
        int digitScore = password.chars().anyMatch(Character::isDigit) ? 2 : 0;
        int symbolScore = password.chars().anyMatch(ch -> "!@#$%^&*()_+[]{}|;:,.<>?".indexOf(ch) >= 0) ? 2 : 0;

        int totalScore = lengthScore + upperScore + lowerScore + digitScore + symbolScore;

        if (totalScore >= 9)
            return "Very Strong";
        if (totalScore >= 7)
            return "Strong";
        if (totalScore >= 5)
            return "Moderate";
        return "Weak";
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.print("Enter password length: ");
        int length = scanner.nextInt();
        scanner.nextLine();

        System.out.print("Include uppercase letters? (yes/no): ");
        boolean useUppercase = scanner.nextLine().equalsIgnoreCase("yes");

        System.out.print("Include lowercase letters? (yes/no): ");
        boolean useLowercase = scanner.nextLine().equalsIgnoreCase("yes");

        System.out.print("Include digits? (yes/no): ");
        boolean useDigits = scanner.nextLine().equalsIgnoreCase("yes");

        System.out.print("Include symbols? (yes/no): ");
        boolean useSymbols = scanner.nextLine().equalsIgnoreCase("yes");

        try {
            String originalPassword = generateComplexPassword(length, useUppercase, useLowercase, useDigits,
                    useSymbols);
            System.out.println("Generated Password: " + originalPassword);
            System.out.println("Password Strength: " + assessPasswordStrength(originalPassword));

            SecretKey secretKey = generateKey();

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            scanner.close();
        }
    }
}
