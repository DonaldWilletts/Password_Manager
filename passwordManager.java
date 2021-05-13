/*
Donald Willetts
Finald Research Project Secure Password Manager
CS:4640 Computer Security

NOTE: I WAS UNABLE TO GET THE USERNAME / PASSWORD ENCRYPTION WORKING. I HAVE DELETED THESE METHODS BECASUE THEY BREAK MY CODE. 
THIS CODE STILL WORKS BY ENCRYPTING THE MASTERFILE AND INSERTING, DELETING, AND SERACHING IT. 
*/
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.util.*;
import java.util.stream.Collectors;
import java.io.File ; 
import java.nio.file.Files;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import java.nio.file.Path;


public class passwordManager
{
    public static void main(String args[]){
        //main to run program
        UserInterfaceClass.welcomeMessage();
        String password = UserInterfaceClass.decideToGetOrCreateMasterPassword();
        byte[] iv = passwordClass.getIVFromPassword(password);
        byte[] key = passwordClass.getKEYFromPassword(password);
        UserInterfaceClass.userCommandSelection(iv, key);

        return ;    
    }
}
class UserInterfaceClass{
    //Welcome message for my program
    public static void welcomeMessage(){
        System.out.println("\n**************************************");
        System.out.println("Welcome to my secure password manager!");
        System.out.println("**************************************");
        System.out.println("\nDetecting if you already have an encrypted masterFile...\n");
    }

    //deciding where to go next, does the masterFile already exist? or does it need to be created?
    public static String decideToGetOrCreateMasterPassword(){
        //masterFile exists! Lets send to a new function to create get the IV / Key
        if(masterFileClass.checkIfMasterFileExists()){
            System.out.println("MasterFile found!");
            String password = UserInterfaceClass.getMasterPasswordFromUser();
            return password;
        }
        else{
            String password = UserInterfaceClass.createMasterFileAndCallPasswordCreater();
            return password;
        }

    }

    //Sending to passwordClass to get key and IV
    private static String getMasterPasswordFromUser(){
        System.out.print("Enter your master password: ");
        Scanner userinput = new Scanner(System.in);
        String password = userinput.nextLine();
        System.out.println(); //This is here to create \n (makes output to terminal prettier)
        //userinput.close();
        return password.toString();
    }

    //Creating masterPasswordfile and generating/getting a password from the user. 
    private static String createMasterFileAndCallPasswordCreater(){

        //Creating masterFile here. 
        System.out.println("Creating your master password file...\n");
        masterFileClass.createMasterFile();
        System.out.println("Master password file created! Would you like to enter or generate a master password? ");

        String password = UserInterfaceClass.askUserToEnterOrGeneratePassword();

        return password;
    }
    
    //ask the user if they want a created password or enter their own password.
    public static String askUserToEnterOrGeneratePassword(){
        //create varible to end loop if user answers correctly. 
        boolean answeredCorrectly = false; 
        String returnPassword = null;

        while (answeredCorrectly != true){
            //Asking if user wants to enter their own or generate a password.
            System.out.println("(type \"g\" to generate password | type \"e\" to enter your own password)");
            System.out.print("Enter Answer here:");
            Scanner userPasswordChoice = new Scanner(System.in);
            String generatePaswordChoice = userPasswordChoice.nextLine();
            System.out.println();
            
            //User choose to generate password
            if (generatePaswordChoice.toString().equals("g")){
                String generatedPassword = passwordClass.createSecurePassword();
                System.out.println("Generated password is: " + generatedPassword);
                System.out.println("\n**Please write down / save this password! If you lose it you cannot recover your passwords!**\n");
                //end loop
                answeredCorrectly = true;
                returnPassword = generatedPassword.toString();
            }
            //User choose to use their own input for a password.
            else if (generatePaswordChoice.toString().equals("e")){
                System.out.print("Enter your own password here: ");
                Scanner userInputPassword = new Scanner(System.in);
                String userCreatedInputPassword = userInputPassword.nextLine();
                System.out.println();
                System.out.println("Your entered password is: " + userCreatedInputPassword);
                System.out.println("\n**Please write down / save this password! If you lose it you cannot recover your passwords!**\n");
                //end loop
                answeredCorrectly = true;
                returnPassword = userCreatedInputPassword.toString();
            }
            else{
                System.out.println("Invaild input. Try again.\n");
            }
        }
        
        //encrypt file after creation
        byte[] iv = passwordClass.getIVFromPassword(returnPassword);
        byte[] key = passwordClass.getKEYFromPassword(returnPassword);
        encrytionClass.setupAndEncrypt(iv, key);
        
        return returnPassword;
    }
    
    //MiddleMan function to ask user what command they want to do
    public static void userCommandSelection(byte[] iv, byte[] key){
        //decrypt at start of function
        decryptionClass.setupAndDecrypt(iv, key);

        Boolean userQuit = false; 
        while (userQuit != true){

            System.out.println("\nPlease enter a command! Options are: ");
            System.out.println("| q to quit \n| s to store new data \n| r to retrieve data \n| c to check if exists \n| cp to change a password \n| rm to remove an instantce \n| gp to generate a secure password");
            System.out.print("Enter command: ");
            Scanner scannerForUserInput = new Scanner(System.in);
            String userSelection = scannerForUserInput.nextLine();
            System.out.println();
            
            //base casse to end loop
            if(userSelection.toString().equals("q")){
                userQuit = true;
            }
            else if(userSelection.toString().equals("s")){
                UserInterfaceClass.storeNewUserData();
            }
            else if(userSelection.toString().equals("r")){
                UserInterfaceClass.retrieveUserData();
            }
            else if(userSelection.toString().equals("c")){
                UserInterfaceClass.checkIfPasswordExists();
            }
            else if(userSelection.toString().equals("cp")){
                UserInterfaceClass.changeAccountPassword(iv, key);
            }
            else if(userSelection.toString().equals("rm")){
                UserInterfaceClass.removeFullUserAccount(iv, key);
            }
            else if(userSelection.toString().equals("gp")){
                UserInterfaceClass.printSecurepassword();
            }
            else{
                System.out.println("Invalid input. Try again. \n");
            }
        }

        //re-encrypt at end of function 
        encrytionClass.setupAndEncrypt(iv, key);
    }

    //store new data
    private static void storeNewUserData() {
        ArrayList<String> dataToWrite = new ArrayList<String>();

        //get and store account name (i.e. Amazon, Google, etc.)
        System.out.print("Enter account name: ");
        Scanner userInput = new Scanner(System.in);
        String accountName = userInput.nextLine().toString();
        dataToWrite.add(accountName);
        System.out.println();

        //get and store username 
        System.out.print("Enter " + accountName + " username: ");
        dataToWrite.add(userInput.nextLine().toString());
        System.out.println();

        //get and store password 
        System.out.print("Enter " + accountName + " password: ");
        dataToWrite.add(userInput.nextLine().toString());
        System.out.println();

        //write this data to masterFile
        masterFileClass.writeToMasterFile(dataToWrite);

        System.out.println("New account information added! You can enter a new command or type \'q\' to quit.");

    }
    //retrieve data
    private static void retrieveUserData(){
        ArrayList<String> accountInfo = new ArrayList<String>();

        System.out.print("Enter the account name to retrieve data: ");
        Scanner userInput = new Scanner(System.in);
        String accountName = userInput.nextLine().toString();

        accountInfo = masterFileClass.getAccountNameUsernamePasswordFromMasterFile(accountName);

        System.out.println("\nHere is your account information:");
        System.out.println("Account Name: " + accountInfo.get(0));
        System.out.println("username: " + accountInfo.get(1));
        System.out.println("password: " + accountInfo.get(2));

        System.out.println("\nAccount information displayed. You can enter a new command or type \'q\' to quit.");

    }
    //check if password exists
    private static void checkIfPasswordExists(){
        Boolean passwordExists;

        System.out.print("Enter the account name to test if data exists: ");
        Scanner userInput = new Scanner(System.in);
        String accountName = userInput.nextLine().toString();

        passwordExists = masterFileClass.existisInMasterFile(accountName);
        System.out.println();
        System.out.println(passwordExists + "! password information exists for this account.");

        System.out.println("\nAccount test was displayed. You can enter a new command or type \'q\' to quit.");
    }
    //remove password information
    private static void removeFullUserAccount(byte[] iv, byte[] key){

        System.out.print("Enter the account name to delete data: ");
        Scanner userInput = new Scanner(System.in);
        String accountName = userInput.nextLine().toString();

        masterFileClass.deleteFromMasterFile(iv, key, accountName);

        System.out.println("\n" +accountName +" information deleted. You can enter a new command or type \'q\' to quit.");

    }
    //change a password
    private static void changeAccountPassword(byte[] iv, byte[] key){
    
        //get accountName
        System.out.print("Enter the account name to change password: ");
        Scanner userInput = new Scanner(System.in);
        String accountName = userInput.nextLine().toString();
        System.out.println();
        
        //get new password
        System.out.print("Enter new "+ accountName+" password: ");
        String newPassword = userInput.nextLine().toString();
        System.out.println();

        //geting all info for specfic account
        ArrayList<String> accountInfo = new ArrayList<String>();
        accountInfo = masterFileClass.getAccountNameUsernamePasswordFromMasterFile(accountName);
        
        //changing old password to new password
        accountInfo.set(2, newPassword);

        //deleting old account info. 
        masterFileClass.deleteFromMasterFile(iv, key, accountName);

        //adding updated info to masterFile
        masterFileClass.writeToMasterFile(accountInfo);

        System.out.println(accountName +" password information Updated! You can enter a new command or type \'q\' to quit.");

    }
    //gen secure password
    private static void printSecurepassword(){
        System.out.println("Secure password: " + passwordClass.createSecurePassword());
        System.out.println("Secure password displayed! You can enter a new command or type \'q\' to quit.");
    }
}

class masterFileClass{

    public static File getMasterFile(){
        File masterFile = new File("masterFile.txt");
        return (masterFile);
    }

    //Checking if password masterFile is in directory 
    public static boolean checkIfMasterFileExists(){
        File masterFile = new File("masterFile.txt");

        boolean exists = masterFile.exists();
            
        return (exists);
     
    }

    //if masterFile is not in directory, create it
    public static void createMasterFile(){
        File masterFile = new File("masterFile.txt");
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

    public static void deleteFromMasterFile(byte[] iv, byte[] key, String accountName){
        
        ArrayList<String> masterFileAsArrayList = readFromMasterFile();
        int accountIndex = masterFileAsArrayList.indexOf(accountName);
        
        //removing files
        masterFileAsArrayList.remove(accountIndex+2);
        masterFileAsArrayList.remove(accountIndex+1);
        masterFileAsArrayList.remove(accountIndex);

        //encrypting file before deleting 
        encrytionClass.setupAndEncrypt(iv, key);

        //getting masterfile and deleting...
        File masterFile = masterFileClass.getMasterFile();
        masterFile.delete();

        //creating new masterfile
        masterFileClass.createMasterFile();
        
        //writing data to new masterFile
        masterFileClass.writeToMasterFile(masterFileAsArrayList);
    }

}

class encrytionClass{
    //citation https://www.novixys.com/blog/java-aes-example/ || I am copying my code from HW3 here. This is the website I cited there as well. 
    
    public static void setupAndEncrypt(byte[] iv, byte[] key)
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

    private static void doEncryptionAndWriteToFile(Cipher cipherContext)
    {
        try{
            
            //File masterFile = new File("C:\\Users\\donwi\\Documents\\GitHub\\Password_Manager\\masterFile.txt");
            File masterFile = new File("masterFile.txt");
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
    private static void doDecryptionAndWriteToFile(Cipher cipherContext)
    {
        //citation https://www.novixys.com/blog/java-aes-example/ || I am copying my code from HW3 here. This is the website I cited there as well. 
        try{
            File masterFile = new File("masterFile.txt");
            Path path = masterFile.toPath();

            byte[] masterFileRawContent = Files.readAllBytes(path);

            byte[] masterFileEncrypted = cipherContext.doFinal(masterFileRawContent);
            
            //setting append to false so old data is overwritten (more secure than being deleted)
            FileOutputStream newMasterFile = new FileOutputStream(masterFile, false);

            newMasterFile.write(masterFileEncrypted);
            newMasterFile.close();
    
        }
        catch (Exception e){
            System.out.println("INCORRECT PASSWORD. TRY AGAIN.");
            System.exit(1);
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
        //https://crypto.stackexchange.com/questions/41436/is-deriving-the-iv-from-the-password-secure 

        final String CHAR_LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
        final String CHAR_UPPERCASE = CHAR_LOWERCASE.toUpperCase();
        final String DIGIT = "0123456789";
        final String SPECIAL_SYMBOLS = "!@#&()–[{}]:;',?/*~$^+=<>";
        final String ALL_CHARACTERS = CHAR_LOWERCASE + CHAR_UPPERCASE + DIGIT + SPECIAL_SYMBOLS;

        //Using this to append characters for my password gen @ the end I will shuffle this to make it random
        StringBuilder password = new StringBuilder(10);
        
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
            
            //salt that I am using is going to be the first 16 bytes of the password (only requirement of a salt is to be globally unique)
            byte[] salt = Arrays.copyOfRange(password.getBytes(), 0, 16);
            
            PBEKeySpec passwordPBKspec = new PBEKeySpec(password.toCharArray(), salt, 1024, 256);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            byte[] createdPBEKS = skf.generateSecret(passwordPBKspec).getEncoded();

            //first 16 bytes of PBEKS
            byte[] key = Arrays.copyOfRange(createdPBEKS, 0, 16);

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

            return IV; 

        }
        catch (Exception e){
            e.printStackTrace();
        }

        return null; 

    }
}