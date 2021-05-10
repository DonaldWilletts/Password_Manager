import java.io.FileInputStream;
import java.io.InputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.OutputStream;
import java.util.*;
import java.util.stream.Collectors;
import java.io.File ; 
import java.nio.file.Files;
import java.nio.*; 
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;

import java.util.concurrent.TimeUnit;

import java.nio.file.Path;

//public static final String masterFilePath = "C:\\Users\\donwi\\Documents\\GitHub\\Password_Manager\\masterFile.txt";

public class passwordManager
{
    public static void main(String args[])
    {
        try{
            /*
            System.out.println("Creating Secure Password...");
            TimeUnit.SECONDS.sleep(1);
            String myPassword = passwordClass.createSecurePassword();
            System.out.println("Your password is: " + myPassword );

            System.out.println("Generating secure IV and Key from password...");
            TimeUnit.SECONDS.sleep(1);
            byte[] key = passwordClass.getKEYFromPassword(myPassword);
            byte[] iv = passwordClass.getIVFromPassword(myPassword); 
            System.out.println("Success!");
            
            Scanner userInput = new Scanner(System.in); 
            System.out.println("Enter Account Name: ");
            String accountName = userInput.nextLine();
            System.out.println("Enter Account Username: ");
            String username = userInput.nextLine();
            System.out.println("Enter Account Password: ");
            String password = userInput.nextLine();
            userInput.close();

            ArrayList<String> arrayToSendToFile = new ArrayList<String>();
            arrayToSendToFile.add(accountName); 
            arrayToSendToFile.add(username); 
            arrayToSendToFile.add(password);
            masterFileClass.writeToMasterFile(arrayToSendToFile); 
            TimeUnit.SECONDS.sleep(7);

            System.out.println("Encrypting masterFile...");
            TimeUnit.SECONDS.sleep(1);
            //create master file here? 
            File masterFile = new File("C:\\Users\\donwi\\Documents\\GitHub\\Password_Manager\\masterFile.txt");
            encrytionClass.setupAndEncrypt("masterFile", iv, key);
            System.out.println("masterFile successfully encrypted!");
            TimeUnit.SECONDS.sleep(7);

            System.out.println("Decrypting masterFile...");
            TimeUnit.SECONDS.sleep(1);
            decryptionClass.setupAndDecrypt(iv, key); 
            System.out.println("masterFile successfully decrypted!");

            Scanner userSearch = new Scanner(System.in); 
            System.out.println("Enter Account Name to search for: ");
            String accountNameToQuery = userSearch.nextLine();
            ArrayList<String> returnList = masterFileClass.getAccountNameUsernamePasswordFromMasterFile(accountNameToQuery);
            System.out.println("Username and Password: " + returnList.toString());

            userSearch.close();

            */
            UserInterfaceClass.welcomeMessage();
            


        }
        catch (Exception e){
            e.printStackTrace();
        }

        return ; 
        
    }
}
class UserInterfaceClass{
    public static void welcomeMessage() throws InterruptedException{
        System.out.println("**************************************");
        System.out.println("Welcome to my secure password manager!");
        System.out.println("**************************************");
        System.out.println("Detecting if you already have an encrypted masterFile...\n");

        if(masterFileClass.checkIfMasterFileExists()){
            System.out.println("MasterFile found!");
            System.out.print("Enter your master password: ");
            Scanner userinput = new Scanner(System.in);
            String password = userinput.nextLine().toString();
            byte[] key = passwordClass.getKEYFromPassword(password);
            byte[] iv = passwordClass.getIVFromPassword(password);
        }
        else{
            System.out.println("Creating your master password file...");
            TimeUnit.SECONDS.sleep(1);
            masterFileClass.createMasterFile();
            System.out.println("Master password file created! Would you like to enter or generate a password?: ");
            Boolean answeredCorrectly = false; 

            while (answeredCorrectly != true){
                System.out.println("(type \"g\" to generate password | type \"e\" to enter your own password)");
                Scanner userPasswordChoice = new Scanner(System.in);
                String generatePaswordChoice = userPasswordChoice.nextLine();
                System.out.println(generatePaswordChoice.toString());
                System.out.println(generatePaswordChoice.toString().equals("g"));
                if (generatePaswordChoice.toString().equals("g")){
                    String generatedPassword = passwordClass.createSecurePassword();
                    System.out.println("your password is: " + generatedPassword);
                    System.out.println("\n**Please write down / save this password! If you lose it you cannot recover your passwords!**\n");
                }
            }
        }
    }
}

class masterFileClass{

    public static File getMasterFile(){
        File masterFile = new File("C:\\Users\\donwi\\Documents\\GitHub\\Password_Manager\\masterFile.txt");
        return (masterFile);
    }

    //Checking if password masterFile is in directory 
    public static boolean checkIfMasterFileExists(){
     
        //change file location on your localmachine
        File masterFile = new File("C:\\Users\\donwi\\Documents\\GitHub\\Password_Manager\\masterFile.txt");

        boolean exists = masterFile.exists();
            
        return (exists);
     
    }

    //if masterFile is not in directory, create it
    public static void createMasterFile(){
        File masterFile = new File("C:\\Users\\donwi\\Documents\\GitHub\\Password_Manager\\masterFile.txt");
        try{
            masterFile.createNewFile();
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }

    //write to masterFile | dataToWrite is List where [accountName, username, password]
    public static void writeToMasterFile(ArrayList<String> dataToWrite){
        //should have already tested if masterFile is avaiable before being called.
        try{
            FileWriter masterFile = new FileWriter("masterFile.txt", true);
            
            for (int i = 0; i < dataToWrite.size(); i++){
                masterFile.write(dataToWrite.get(i) + System.lineSeparator());
            }

            masterFile.close();
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }

    //read from masterFile | reading data into an array and will sort data in a different function 
    public static ArrayList<String> readFromMasterFile(){
        
        ArrayList<String> returnArray = new ArrayList<String>();

        try{
            //citation https://stackoverflow.com/questions/5343689/java-reading-a-file-into-an-arraylist
            Scanner fileScanner = new Scanner(new File("masterFile.txt"));
            
            while(fileScanner.hasNext()){
                returnArray.add(fileScanner.next());
            }

            fileScanner.close();

            return (returnArray); 
        }
        catch (Exception e){
            e.printStackTrace();
        }

        return (null);
        
    }

    public static Boolean existisInMasterFile(String searchString){
        ArrayList<String> masterFileAsArrayList = readFromMasterFile();

        return(masterFileAsArrayList.contains(searchString));
    }

    public static ArrayList<String> getAccountNameUsernamePasswordFromMasterFile(String accountName){
        ArrayList<String> masterFileAsArrayList = readFromMasterFile();
        int accountIndex = masterFileAsArrayList.indexOf(accountName);

        String accountName2 = masterFileAsArrayList.get(accountIndex);
        String username = masterFileAsArrayList.get(accountIndex+1);
        String password = masterFileAsArrayList.get(accountIndex+2);

        ArrayList<String> returnListOfQueriedData = new ArrayList<String>(); 
        returnListOfQueriedData.add(accountName2);
        returnListOfQueriedData.add(username);
        returnListOfQueriedData.add(password);

        return returnListOfQueriedData; 

    }
}

class encrytionClass{
    //citation https://www.novixys.com/blog/java-aes-example/ || I am copying my code from HW3 here. This is the website I cited there as well. 
    
    public static void setupAndEncrypt(String masterFile, byte[] iv, byte[] key)
    {
       
        try{

            // Generate IvParameterSpec object from IV Raw Data 
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            // Generate AES Key through KeyGenerator and SecretKey (handle exception with try-catch)
            SecretKey skey = new SecretKeySpec(key, "AES");

            //Create a Cipher object with "AES/CBC/PKCS5Padding" (handle exception with try-catch)
            Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");

            // Initialize the cipher object with the secret key and IV parameter spec obtain before 
            ci.init(Cipher.ENCRYPT_MODE, skey, ivspec);

            //Call the doEncryption function to actually encrypt the file and output the ciphertext in the output file 
            doEncryptionAndWriteToFile(ci);

        }
        catch (Exception catchedExeption)
        {
            catchedExeption.printStackTrace();
        }

    }

    public static void doEncryptionAndWriteToFile(Cipher cipherContext)
    {
        try{
            
            File masterFile = new File("C:\\Users\\donwi\\Documents\\GitHub\\Password_Manager\\masterFile.txt");
            Path path = masterFile.toPath();

            byte[] masterFileRawContent = Files.readAllBytes(path);

            byte[] masterFileEncrypted = cipherContext.doFinal(masterFileRawContent);
            
            //setting append to false so old data is overwritten (more secure than being deleted)
            FileOutputStream newMasterFile = new FileOutputStream(masterFile, false);

            newMasterFile.write(masterFileEncrypted);
            newMasterFile.close();

        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }

}

class decryptionClass{
    public static byte[] readByteFromFile(String inputFileName, int dataSize)
    {
        byte[]  rawData = new byte[dataSize]; 
        try {
            FileInputStream inFile = new FileInputStream(inputFileName);
            int bytesRead ; 
            if((bytesRead = inFile.read(rawData))!=-1){
                if(bytesRead == dataSize){
                    return rawData ;
                }
                else{
                    System.out.println("ERROR: Expected reading " + dataSize + "bytes but found " + bytesRead + "bytes in the file: " + inputFileName);
                    System.exit(20);
                    return null ; 
                }
            }
            else{
                System.out.println("ERROR: Could read raw data from the file: " + inputFileName);
                System.exit(20);
                return null ; 
            }

        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("ERROR: Could read raw data from the file: " + inputFileName);
            System.exit(20);
            return null ; 
        }

        

    }
    
    public static void doDecryptionAndWriteToFile(Cipher cipherContext)
    {
        //citation https://www.novixys.com/blog/java-aes-example/ || I am copying my code from HW3 here. This is the website I cited there as well. 
        try{
            
            File masterFile = new File("C:\\Users\\donwi\\Documents\\GitHub\\Password_Manager\\masterFile.txt");
            Path path = masterFile.toPath();

            byte[] masterFileRawContent = Files.readAllBytes(path);

            byte[] masterFileEncrypted = cipherContext.doFinal(masterFileRawContent);
            
            //setting append to false so old data is overwritten (more secure than being deleted)
            FileOutputStream newMasterFile = new FileOutputStream(masterFile, false);

            newMasterFile.write(masterFileEncrypted);
            newMasterFile.close();
    
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }

    public static void setupAndDecrypt(byte[] iv, byte[] key)
    {
        
        try
        {   
            // Generate IvParameterSpec object from raw IV bytes  
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            //create a secret key spec object from raw key bytes and for "AES" algorithm (handle exception with try-catch)
            SecretKeySpec skey = new SecretKeySpec(key, "AES");
            
            //Create a Cipher object with "AES/CBC/PKCS5Padding" (handle exception with try-catch)
            Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
            
            // Initialize the cipher object with the secret key and IV parameter spec obtain before in the Cipher.DECRYPT_MODE
            ci.init(Cipher.DECRYPT_MODE, skey, ivSpec);

            //Call the doEncryption function
            doDecryptionAndWriteToFile(ci);
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
       
    }
}

class passwordClass{
    
    public static String createSecurePassword(){

        //Ciataion I referenced this code while creating my password creater: https://mkyong.com/java/java-password-generator-example/ 
        //https://mkyong.com/java/java-password-generator-example/
        //https://crypto.stackexchange.com/questions/41436/is-deriving-the-iv-from-the-password-secure 

        final String CHAR_LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
        final String CHAR_UPPERCASE = CHAR_LOWERCASE.toUpperCase();
        final String DIGIT = "0123456789";
        final String SPECIAL_SYMBOLS = "!@#&()–[{}]:;',?/*~$^+=<>";
        final String ALL_CHARACTERS = CHAR_LOWERCASE + CHAR_UPPERCASE + DIGIT + SPECIAL_SYMBOLS;

        //Using this to append characters for my password gen @ the end I will shuffle this to make it random
        StringBuilder password = new StringBuilder(8);
        
        //get 2 lowercase letters
        password.append(getRandomCharacters(CHAR_LOWERCASE, 2));

        //get 2 uppercase letters
        password.append(getRandomCharacters(CHAR_UPPERCASE, 2));

        //get 2 digits
        password.append(getRandomCharacters(DIGIT, 2));

        //get 2 special symbols 
        password.append(getRandomCharacters(SPECIAL_SYMBOLS, 2));

        //get 2 random
        password.append(getRandomCharacters(ALL_CHARACTERS, 2));

        //shuffle characters
        List<String> shufflePassword = Arrays.asList(password.toString().split(""));
        Collections.shuffle(shufflePassword);
        String finalPassword = shufflePassword.stream().collect(Collectors.joining());

        return (finalPassword);

    }

    private static String getRandomCharacters(String inputString, int amountToSendBack){
        try{
            //Code sourced from https://howtodoinjava.com/java8/secure-random-number-generation/ 
            SecureRandom secureRandomGen = SecureRandom.getInstance("SHA1PRNG","SUN");
            
            StringBuilder returnStr = new StringBuilder(amountToSendBack);

            for (int i = 0; i < amountToSendBack; i++){
                //get random int between 0 and the length of the strong 
                int randomInteger = secureRandomGen.nextInt(inputString.length()-1);

                returnStr.append(inputString.charAt(randomInteger));

            }

            return (returnStr.toString());
        }
        catch (Exception e){
            e.printStackTrace();
        }

        return (null);

    }

    public static byte[] getKEYFromPassword(String password){
        try{
            //citation: https://howtodoinjava.com/java/java-security/how-to-generate-secure-password-hash-md5-sha-pbkdf2-bcrypt-examples/
            //citation: https://crypto.stackexchange.com/questions/41436/is-deriving-the-iv-from-the-password-secure
            
            //salt that I am using is going to be the first 16 bytes of the password (only require of a salt is to be globally unique)
            byte[] salt = Arrays.copyOfRange(password.getBytes(), 0, 16);
            
            PBEKeySpec passwordPBKspec = new PBEKeySpec(password.toCharArray(), salt, 1024, 256);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            byte[] createdPBEKS = skf.generateSecret(passwordPBKspec).getEncoded();

            //first 16 bytes of PBEKS
            byte[] key = Arrays.copyOfRange(createdPBEKS, 0, 16);

            //System.out.println(key.length);

            return key; 

        }
        catch (Exception e){
            e.printStackTrace();
        }

        return null; 

    }

    public static byte[] getIVFromPassword(String password){
        try{
            //citation: https://howtodoinjava.com/java/java-security/how-to-generate-secure-password-hash-md5-sha-pbkdf2-bcrypt-examples/
            //citation: https://crypto.stackexchange.com/questions/41436/is-deriving-the-iv-from-the-password-secure
            
            //salt that I am using is going to be the first 16 bytes of the password (only require of a salt is to be globally unique)
            byte[] salt = Arrays.copyOfRange(password.getBytes(), 0, 16);
            
            PBEKeySpec passwordPBKspec = new PBEKeySpec(password.toCharArray(), salt, 1024, 256);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            byte[] createdPBEKS = skf.generateSecret(passwordPBKspec).getEncoded();

            //IV is the next 16 bytes after key
            byte[] IV = Arrays.copyOfRange(createdPBEKS, 16, 32);

            //System.out.println(IV.length);

            return IV; 

        }
        catch (Exception e){
            e.printStackTrace();
        }

        return null; 

    }
}
