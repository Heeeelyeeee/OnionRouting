package com.example.directorynode.Controller;
import com.example.directorynode.Model.NodeModel;
import org.springframework.web.bind.annotation.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.*;
import java.util.concurrent.TimeUnit;


@RestController
@CrossOrigin
public class DirectoryNodeController {
    ArrayList<NodeModel> nodeModelArrayList = new ArrayList<>();
    ArrayList<byte[]> publicKeys = new ArrayList<>();

    /**
     * Adds Node into Notary of nodes that are available
     * @param portnr info about where the node is running
     */
    @PostMapping("/")
    public void greeting(@RequestParam(name = "PORTNR") String portnr){
        NodeModel nodeModel = new NodeModel(portnr);
        boolean add = true;
        for (int i = 0; i<nodeModelArrayList.size(); i++){
            if(nodeModelArrayList.get(i).portnr.equals(nodeModel.portnr)){
                add = false;
            }
        }
        if(add){
            System.out.println("added :       " + portnr);
            nodeModelArrayList.add(nodeModel);
        }

    }

    /**
     * Get all public keys
     * @param hvilkenPB
     * @return
     */
    @GetMapping("/getPublicKeys/")
    public byte[] getPublickeys(@RequestParam(name = "HvilkenPB") int hvilkenPB){
        ByteArrayOutputStream bytearray = new ByteArrayOutputStream();
        bytearray.writeBytes(publicKeys.get(hvilkenPB));

        return bytearray.toByteArray();

    }

    /**
     * adds public key to array of public keys
     * @param inputstream
     * @throws IOException
     * @throws InterruptedException
     */
    @PutMapping("/publicKey/")
    public void addPublickeys(InputStream inputstream) throws IOException, InterruptedException {

        boolean gotMessage = false;

        ByteArrayOutputStream bytearray = new ByteArrayOutputStream();
                while(!gotMessage){


                    byte[] buffer = new byte[1024];
                    int bytesRead;
                    while (inputstream.available() > 0 && (bytesRead = inputstream.read(buffer, 0, buffer.length)) > 0) {
                        bytearray.write(buffer, 0, bytesRead);
                        TimeUnit.MILLISECONDS.sleep(200);
                        if(inputstream.available() == 0){
                            gotMessage = true;
                        }

                    }

                }
                //idk if the publickey is enccoded right
        /*System.out.println("regexBytes:"+Arrays.toString("!pkfn!".getBytes(StandardCharsets.UTF_8)));
        System.out.println("regexToStringAgain:" + new String("!pkfn!".getBytes(StandardCharsets.UTF_8)));

         */
        publicKeys.add(Base64.getEncoder().encode(bytearray.toByteArray()));
        System.out.print("addedKey:     ");
        System.out.println(Arrays.toString(bytearray.toByteArray()));



    }

    /**
     * Deletes a given public key from the Array of public keys
     * @param inputstream
     * @throws IOException
     * @throws InterruptedException
     */
    @PutMapping("/Delete/publicKey/")
    public void DeletePublickeys(InputStream inputstream) throws IOException, InterruptedException {
        System.out.println("called deletion");
        boolean gotMessage = false;

        ByteArrayOutputStream bytearray = new ByteArrayOutputStream();
        while(!gotMessage){


            byte[] buffer = new byte[1024];
            int bytesRead;
            while (inputstream.available() > 0 && (bytesRead = inputstream.read(buffer, 0, buffer.length)) > 0) {
                bytearray.write(buffer, 0, bytesRead);
                TimeUnit.MILLISECONDS.sleep(200);
                if(inputstream.available() == 0){
                    gotMessage = true;
                }

            }

        }
        if(publicKeys.contains(bytearray.toByteArray())){
            publicKeys.remove(bytearray.toByteArray());
            System.out.println("Delete a Key");
        }


    }


    /**
     * Gets all the nodes stored
     * @return
     */
    @GetMapping("/")
    public String get(){
        String allNodes = "";
        for(int i = 0; i< nodeModelArrayList.size(); i++){
            allNodes = allNodes + nodeModelArrayList.get(i).portnr +"<!!!>";
        }

        System.out.println("List of all:  " + allNodes);
        return  allNodes;
    }

    /**
     * Deletes a given node if it is found in the list
     * @param portnr
     */
    @PostMapping("/DELETE/")
    public void delete(@RequestParam(name = "PORTNR")String portnr){
        NodeModel nodeModel = new NodeModel(portnr);
        for (int i = 0; i<nodeModelArrayList.size(); i++){
            if(nodeModelArrayList.get(i).portnr.equals(nodeModel.portnr)){
                nodeModelArrayList.remove(i);
                System.out.println("Deleted :     " + portnr);
            }
        }
    }
}
