# Anonion - My http request OnionRoutingService

## Intro

This is a Service that lets a client connect to a series of nodes, to ensure more secure and anonymous http requests.
The http request the client sends are encrypted with high security encryption. The program works by setting up a secure
tunnel with a series of nodes (currently 3 nodes) and then the last node in the series will make a normal http request
to a given server. 

This is a service that is dependent on its popularity to be useful, because the nodes cannot be hosted on a few possible
hosts as this would cause a security hazard. 

This project contains a Client program, Directory node program, and a node program. These programs together is all that is necessary
to host nodes, run a server which keeps track of all nodes, and use the node network through a client. 

It would be optimal to run these programs all on different machines, but for now I guess one test device will be sufficient.


## Implemented functionality

* Sending http GET requests, and getting full response. 
  
* Anonymity to client though hybrid encryption.

## Future work
_Here we gooooooo....._
* Should implement a proxy server which redirects all http request thorough the application
* Implement other http requests, such as POST.
* Implement the option to use more than just 3 nodes.
* Implement threading for nodes, so that more than one client can be using a given Node.
* Implement more flexibility for user, as it is currently hardcoded to get a response from http://datakom.no/
* Remove bug. There is a too long key being transported in the initialization phase of the program.
    This bug causes one node to shut down which forces you to restart all programs to retry.
  This happens approximately 1/12 of the time trying to start the client program.
* Implement a check to se if Nodes are still running. This check should be done by the server. if the Node is down,
unresponsive, the directory node should remove them from the list of available nodes. 

## Dependencies
* webFramework for Java, Springboot. This is used for the directory node.

## Installation Guide And How To Use


install Java: https://www.java.com/en/download/help/windows_manual_download.html
install maven: https://maven.apache.org/install.html

Open up a cmd prompt and navigate to the root folder of the DirectoryNode folder.
Here you will input `mvn spring-boot:run`

After this you will have to compile the node program and run 3 instances of it. 
in the directory with the Node program write this in the command window to compile `javac Node.java`
Now you can run 3 instances of the program with `java Node`

With all that setup you can now run the client. Navigate to the directory with the Client.java program and run this in the commandline:
`javac Client.java` and then `java Client`. Here you will wait for a couple of seconds while client is setting up the path to the different nodes and sending AES keys,
after that you will be promoted with a text that tells you what to do.

    
## API docs
API for the directory node :)

* POST methode for adding Node to directoryNode
    *URL: `"/"`
    *PARAMS: `PORTNR` Ip, splitRegex, and port which the node is running on. 

* GET methode for getting all Nodes which are available
    *URL: `"/"`
    *PARAMS: None
  
* GET methode for getting all public RSA keys from nodes
    *URL:` "/getPublicKeys/"`
    *PARAMS: Nonde
  
* PUT methode for setting public for nodes from InputStream
    *URL: `"/publicKey/" `
    *PARAMS: None
  
* PUT methode for deleting Public key from directoryNode. Expects a input stream for identifying which key to delete.
    *URL: `"/Delete/publicKey/"`
    *PARAMS: None
  
* POST methode for deleting Node from directoryNode.
    *URL: `"/DELETE/"`
    *PARAMS: `PORTNR`  Ip, splitRegex, and port which the node is running on.