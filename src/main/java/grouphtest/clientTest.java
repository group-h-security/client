package grouphtest;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;

public class clientTest {

     private boolean httpConnectTest() {//test method for flask server
            try {

               URI httpURI = new URI("http://127.0.0.1:5000/");//setting the URI to the flask / should just return json obj, lets us know its hitting the endpoints as expected                                                    // endpoint
               URL httpURL = httpURI.toURL();// setting it to the URL
               HttpURLConnection httpCon = (HttpURLConnection) httpURL.openConnection();//open conn to flask server
               httpCon.setRequestMethod("GET");// setting to GET request

               int statusCode = httpCon.getResponseCode();// grab the statusCode from the flask conn

                if (statusCode == 200) {//if it responds as expected
                   BufferedReader sr = new BufferedReader(new InputStreamReader(httpCon.getInputStream()));// wrap inp stream reader in buffered reader to grab the returned json 
                   String n;//n will represent each line
                   while ((n = sr.readLine()) != null) {//read until theres no more to read
                      System.out.println(n);
                   }
                   sr.close();//closing the br to prevent leaks
                   return true;
                }

            } catch (Exception exc) {
               System.err.println("Failed connecting to CAServoce" + exc.getMessage());
            }
            return false;// failed conn
        }

        private void testServerConn(){


        }

        private void testMessageHandling(){

        }

}
