package restcloud;


import java.io.File;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;


  @Configuration 
  public class Config {
  
  @Value("${cloud.aws.credentials.access-key}") private String awsAccessKey;
  
  @Value("${cloud.aws.credentials.secret-key}") private String awsSecretKey;
  
  BasicAWSCredentials credentials = new BasicAWSCredentials(
		  "<AWS accesskey>", 
		  "<AWS secretkey>"
		);
  
  @Primary
  @Bean 
  public AmazonS3 createClient() {
	  AmazonS3 s3 = AmazonS3ClientBuilder.standard()
			    .withCredentials(new AWSStaticCredentialsProvider(credentials))
			    .withEndpointConfiguration(
			        new AmazonS3ClientBuilder.EndpointConfiguration(
			            "storage.yandexcloud.net","ru-central1"
			        )
			    )
			    .build();
	  return s3;
  }
  }
 