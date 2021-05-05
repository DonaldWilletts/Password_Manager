import java.io.FileInputStream;
import java.io.InputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.OutputStream;
import java.util.*;
import java.io.File ; 
import java.nio.*; 

//public static final String masterFilePath = "C:\\Users\\donwi\\Documents\\GitHub\\Password_Manager\\masterFile.txt";

public class passwordManager
{
    public static void main(String args[])
    {
        
        ArrayList<String> inputData = new ArrayList<String>(); 
        inputData.add("test");
        inputData.add("hello");
        inputData.add("there");
        masterFileClass.writeToMasterFile(inputData);
        

        ArrayList<String> myData = masterFileClass.readFromMasterFile();

        System.out.println(myData.toString());
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
        }
        catch (Exception e){
            e.printStackTrace();
        }

        return (returnArray);
    }
}