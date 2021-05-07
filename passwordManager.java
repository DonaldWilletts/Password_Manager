import java.io.FileInputStream;
import java.io.InputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.OutputStream;
import java.util.*;
import java.io.File ; 
import java.nio.file.Files;
import java.nio.*; 
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.nio.file.Path;

//public static final String masterFilePath = "C:\\Users\\donwi\\Documents\\GitHub\\Password_Manager\\masterFile.txt";

public class passwordManager
{
    public static void main(String args[])
    {
        
        //ArrayList<String> inputData = new ArrayList<String>(); 
        //inputData.add("Account Name");
        //inputData.add("Username");
        //inputData.add("Password");
        //masterFileClass.writeToMasterFile(inputData);
        

        //ArrayList<String> myData = masterFileClass.readFromMasterFile();

        //System.out.println(myData.toString());

        //encrytionClass.setupAndEncrypt(args[0], args[1], args[2], args[3]);

        //decryptionClass.setupAndDecrypt(args[0], args[1], args[2], args[3]);

        return ; 
        
    }
}

class masterFileClass{

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
            FileWriter masterFile = new FileWriter("masterFile.txt");
            
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

}

class encrytionClass{
    //citation https://www.novixys.com/blog/java-aes-example/ || I am copying my code from HW3 here. This is the website I cited there as well. 
    
    public static void setupAndEncrypt(String inputPlaintextFile, String outputKeyFile, String outputIVFile, String outputCiphertextFile)
    {
       
        try{

            // Generate Raw IV Data using IVGen function 
            byte[] iv = IVGen(); 

            // Write Raw IV data to the file name provided by outputIVFile  
            writeByteToFile(iv, outputIVFile);

            // Generate IvParameterSpec object from IV Raw Data 
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            // Generate AES Key through KeyGenerator and SecretKey (handle exception with try-catch)
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            SecretKey skey = kgen.generateKey();

            // Obtain raw key bytes from the SecretKey instance 
            byte[] keyb = skey.getEncoded(); 

            //Write raw key bytes into the filed name provided by outputKeyFile 
            writeByteToFile(keyb, outputKeyFile);

            //Create a Cipher object with "AES/CBC/PKCS5Padding" (handle exception with try-catch)
            Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");

            // Initialize the cipher object with the secret key and IV parameter spec obtain before 
            ci.init(Cipher.ENCRYPT_MODE, skey, ivspec);

            //Call the doEncryption function to actually encrypt the file and output the ciphertext in the output file 
            doEncryptionAndWriteToFile(ci, inputPlaintextFile);

        }
        catch (Exception catchedExeption)
        {
            catchedExeption.printStackTrace();
        }

    }

    public static byte[] IVGen()
    { 
        try{
            SecureRandom sRandom = SecureRandom.getInstance("SHA1PRNG","SUN");
        
            byte[] iv = new byte[128/8];
            sRandom.nextBytes(iv);

            return (iv);
        }
        catch (Exception catchedExeption)
        {
            catchedExeption.printStackTrace();
        }
        return (null); 
    }

    public static void writeByteToFile(byte[] data, String outputFileName)
    {
        FileOutputStream outputFile = null;
        try {
            outputFile = new FileOutputStream(outputFileName);
            outputFile.write(data);
            System.out.println("Wrote " + data.length + "bytes in the file: " + outputFileName); 
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("ERROR: Couldn't write to file: " + outputFileName);
        }
    }

    public static void doEncryptionAndWriteToFile(Cipher cipherContext, String inputPlaintextFile)
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
    
    public static void doDecryptionAndWriteToFile(Cipher cipherContext, String outputPlaintextFile, String inputCiphertextFile)
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

    public static void setupAndDecrypt(String outputPlaintextFile, String inputKeyFile, String inputIVFile, String inputCiphertextFile)
    {
        
        try
        {   
            // load raw IV bytes from the file given by inputIVFile (Use readBytesFromFile) IV LENGTH = 16 BYTES
            byte[] rawIV = readByteFromFile(inputIVFile,16);

            // Generate IvParameterSpec object from raw IV bytes  
            IvParameterSpec ivSpec = new IvParameterSpec(rawIV);

            // load raw key bytes from the file given by inputKeyFile (Use readBytesFromFile) KEY LENGTH = 16 bytes 
            byte[] rawKey = readByteFromFile(inputKeyFile,16);

            //create a secret key spec object from raw key bytes and for "AES" algorithm (handle exception with try-catch)
            SecretKeySpec skey = new SecretKeySpec(rawKey, "AES");
            
            //Create a Cipher object with "AES/CBC/PKCS5Padding" (handle exception with try-catch)
            Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
            
            // Initialize the cipher object with the secret key and IV parameter spec obtain before in the Cipher.DECRYPT_MODE
            ci.init(Cipher.DECRYPT_MODE, skey, ivSpec);

            //Call the doEncryption function
            doDecryptionAndWriteToFile(ci, outputPlaintextFile, inputCiphertextFile);
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

        //Using this to append characters for my password gen @ the end I will shuffle this to make it random
        StringBuilder password = new StringBuilder(8);
        
        //String twoLowerCaseChars = generateRandom

    }

    private static String getRandomCharacters(String inputString, int amountToSendBack){
        try{
            //Code sourced from https://howtodoinjava.com/java8/secure-random-number-generation/ 
            SecureRandom secureRandomGen = SecureRandom.getInstance("SHA1PRNG","SUN");
            
            //StringBuilder returnStr = new StringBuilder(amountToSendBack);
            String returnStr = new St; 

            for (int i = 0; i < amountToSendBack; i++){
                //get random int between 0 and the length of the strong 
                int randomInteger = secureRandomGen.nextInt(inputString.length()-1);

                returnStr = returnStr + inputString.substring(randomInteger);

            }

            

        }
        catch (Exception e){
            e.printStackTrace();
        }
    }

}
