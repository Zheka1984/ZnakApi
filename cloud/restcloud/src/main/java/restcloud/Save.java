package restcloud;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.stream.annotation.EnableBinding;
import org.springframework.cloud.stream.annotation.StreamListener;
import org.springframework.cloud.stream.messaging.Sink;


@EnableBinding(Sink.class)
@SpringBootApplication
public class Save {

	public static void main(String... args) {
		SpringApplication.run(Save.class, args);
	}
	
	  @StreamListener(Sink.INPUT) public void handleMessage(String str){
	  System.out.println("Received Message is: " + str); }
	 
}
