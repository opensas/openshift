package controllers;

import java.util.Map;
import java.util.Properties;

import play.mvc.Controller;

public class Application extends Controller {

    public static void index() {
    	
    	Properties playProperties = play.Play.configuration;
    	
    	Properties properties = System.getProperties();
    	
    	Map<String,String> environment = System.getenv();
  	
        render(playProperties, properties, environment);
    }

}