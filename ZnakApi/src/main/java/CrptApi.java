import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.objsys.asn1j.runtime.Asn1BerDecodeBuffer;
import com.objsys.asn1j.runtime.Asn1BerEncodeBuffer;
import com.objsys.asn1j.runtime.Asn1Null;
import com.objsys.asn1j.runtime.Asn1ObjectIdentifier;
import com.objsys.asn1j.runtime.Asn1OctetString;

import okhttp3.Call;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import ru.CryptoPro.Crypto.CryptoProvider;
import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.CMSVersion;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.CertificateChoices;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.CertificateSet;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.ContentInfo;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.DigestAlgorithmIdentifier;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.DigestAlgorithmIdentifiers;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.EncapsulatedContentInfo;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.IssuerAndSerialNumber;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.SignatureAlgorithmIdentifier;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.SignatureValue;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.SignedData;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.SignerIdentifier;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.SignerInfo;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.SignerInfos;
import ru.CryptoPro.JCP.ASN.PKIX1Explicit88.CertificateSerialNumber;
import ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Name;
import ru.CryptoPro.JCP.params.OID;
import ru.CryptoPro.JCP.tools.Array;
import ru.CryptoPro.JCSP.JCSP;
import ru.CryptoPro.reprov.RevCheck;


public class CrptApi {
	
	public static void main(String[] args) throws Exception {
		CrptApi.VvodVOborot.Description desc = new CrptApi.VvodVOborot.Description();
		desc.setParticipantInn("775624987522");
		VvodVOborot vvo = new VvodVOborot();
		vvo.setDescription(desc);
		vvo.setDoc_id("15240");
		vvo.setDoc_type("тестовый документ");
		vvo.setImportRequest("нет");
		vvo.setOwner_inn("615290158489");
		vvo.setParticipant_inn("25897871552");
		Product prod1 = new Product();
		Product prod2 = new Product();
		prod1.setCertificate_document("sertdoc");
		prod1.setCertificate_document_date("02012015");
		prod1.setCertificate_document_number("10");
		prod1.setOwner_inn("52546154789");
		prod1.setProducer_inn("779652368974");
		prod1.setProduction_date("15102016");
		//prod1.setTnved_code("156321");
		prod1.setUit_code("150216");
		prod2.setCertificate_document("sertdoc45");
		prod2.setCertificate_document_date("02012016");
		prod2.setCertificate_document_number("11");
		prod2.setOwner_inn("52546154789");
		prod2.setProducer_inn("779652368974");
		prod2.setProduction_date("15102016");
		prod2.setTnved_code("156321");
		prod2.setUit_code("150216");
		List<Product> list = new ArrayList<>();
		list.add(prod1); list.add(prod2);
		vvo.setProducts(list);
		new HTTPRequests().createXML(vvo);
	}
public CrptApi(TimeUnit timeUnit, int requestLimit) {	
	}

    private static class Auth{
    	String token = null;
    	String uuid = null;
    	String data = null;
    	public void auth() throws IOException {
    		OkHttpClient client = new OkHttpClient();
    		ObjectMapper objectMapper = new ObjectMapper();
    		Sign sign = new Sign();
    		Request request = new Request.Builder()
    			      .url("https://ismp.crpt.ru/api/v3/auth/cert/key")
    			      .build();
    		Call call = client.newCall(request);
    		Response response = call.execute();
    		String jsonData = response.body().string();
    		JsonNode jsonNode = objectMapper.readTree(jsonData);
    		uuid = jsonNode.get("uuid").asText();  
    		data = jsonNode.get("data").asText();
    		sign.
    		
    	}
    }
	private static class Sign{
		
		 public byte[] createCMS(byte[] buffer, byte[] sign, Certificate cert, boolean detached) 
				 throws Exception {
		        ContentInfo all = new ContentInfo();
		        all.contentType = new Asn1ObjectIdentifier((new OID("1.2.840.113549.1.7.2")).value);
		        SignedData cms = new SignedData();
		        all.content = cms;
		        cms.version = new CMSVersion(1L);
		        cms.digestAlgorithms = new DigestAlgorithmIdentifiers(1);
		        DigestAlgorithmIdentifier a = new DigestAlgorithmIdentifier((new OID("1.2.643.7.1.1.2.2")).value);
		        a.parameters = new Asn1Null();
		        cms.digestAlgorithms.elements[0] = a;
		        if (detached) {
		            cms.encapContentInfo = new EncapsulatedContentInfo(new Asn1ObjectIdentifier((new OID("1.2.840.113549.1.7.1")).value), (Asn1OctetString)null);
		        } else {
		            cms.encapContentInfo = new EncapsulatedContentInfo(new Asn1ObjectIdentifier((new OID("1.2.840.113549.1.7.1")).value), new Asn1OctetString(buffer));
		        }

		        cms.certificates = new CertificateSet(1);
		        ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Certificate certificate = new ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Certificate();
		        Asn1BerDecodeBuffer decodeBuffer = new Asn1BerDecodeBuffer(cert.getEncoded());
		        certificate.decode(decodeBuffer);
		        cms.certificates.elements = new CertificateChoices[1];
		        cms.certificates.elements[0] = new CertificateChoices();
		        cms.certificates.elements[0].set_certificate(certificate);
		        cms.signerInfos = new SignerInfos(1);
		        cms.signerInfos.elements[0] = new SignerInfo();
		        cms.signerInfos.elements[0].version = new CMSVersion(1L);
		        cms.signerInfos.elements[0].sid = new SignerIdentifier();
		        byte[] encodedName = ((X509Certificate)cert).getIssuerX500Principal().getEncoded();
		        Asn1BerDecodeBuffer nameBuf = new Asn1BerDecodeBuffer(encodedName);
		        Name name = new Name();
		        name.decode(nameBuf);
		        CertificateSerialNumber num = new CertificateSerialNumber(((X509Certificate)cert).getSerialNumber());
		        cms.signerInfos.elements[0].sid.set_issuerAndSerialNumber(new IssuerAndSerialNumber(name, num));
		        cms.signerInfos.elements[0].digestAlgorithm = new DigestAlgorithmIdentifier((new OID("1.2.643.7.1.1.2.2")).value);
		        cms.signerInfos.elements[0].digestAlgorithm.parameters = new Asn1Null();
		        cms.signerInfos.elements[0].signatureAlgorithm = new SignatureAlgorithmIdentifier((new OID("1.2.643.7.1.1.1.1")).value);
		        cms.signerInfos.elements[0].signatureAlgorithm.parameters = new Asn1Null();
		        cms.signerInfos.elements[0].signature = new SignatureValue(sign);
		        Asn1BerEncodeBuffer asnBuf = new Asn1BerEncodeBuffer();
		        all.encode(asnBuf, true);
		        return asnBuf.getMsgCopy();
		    }
		 public Signature readAndHash(Signature signature, String fileName) throws Exception {
		        File file = new File(fileName);
		        FileInputStream fData = new FileInputStream(file);
		        int read;
		        while ( (read = fData.read()) != -1) {
		            signature.update((byte)read);
		        }
		        fData.close();
		        return signature;
		    }
		public byte[] sign(String alias, String fileName, boolean detached) throws Exception {
			byte[] cms = null;
			System.setProperty("file.encoding", "UTF-8");
			Security.addProvider(new JCP());
			Security.addProvider(new JCSP()); // провайдер JCSP
			Security.addProvider(new RevCheck());// провайдер проверки сертификатов JCPRevCheck
			//(revocation-провайдер)
			Security.addProvider(new CryptoProvider());// провайдер шифрования JCryptoP/
			//KeyStore keyStore = KeyStore.getInstance("HDIMAGE", "JCSP");
			KeyStore keyStore = KeyStore.getInstance(JCP.HD_STORE_NAME, "JCP");
			keyStore.load(null, null);
			PrivateKey pk = (PrivateKey) keyStore.getKey(alias, "12345678".toCharArray());
			X509Certificate certificate = (X509Certificate)keyStore.getCertificate(alias);
			Signature signature = Signature.getInstance("GOST3411_2012_256withGOST3410DH_2012_256");
	        signature.initSign(pk);
	        readAndHash(signature, fileName); // signature.update
	        if(detached)
	        cms = createCMS(null, signature.sign(), certificate, false);
	        else {
	        cms = createCMS(Files.readAllBytes(new File(fileName).toPath()), signature.sign(), certificate, false);
	        }
	        return Base64.getEncoder().encode(cms);
		}
	} 
	private static class HTTPRequests{
		ObjectMapper mapper = new ObjectMapper();
		public String createXML(Document doc) throws JsonProcessingException  {
			String result = null;
			if(doc.getTypeOfDocument().equals("ВводВОборот")) {
				String jsonInString = mapper.writeValueAsString(doc);
				System.out.println(jsonInString);
			}
			return null;
		}
	}
	
	private static class VvodVOborot implements Document{
		@JsonIgnore
		@Override
		public String getTypeOfDocument() {
			return "ВводВОборот";
		}
		private Description description = null;
		private String doc_id = null;
		private String doc_type = null;
		private String importRequest = null;
		private String owner_inn = null;
		private String participant_inn = null;
		private List<Product> products = new ArrayList<>();
 
		public Description getDescription() {
			return description;
		}
		public String getDoc_id() {
			return doc_id;
		}
		public String getDoc_type() {
			return doc_type;
		}
		public String getImportRequest() {
			return importRequest;
		}
		public String getOwner_inn() {
			return owner_inn;
		}
		public String getParticipant_inn() {
			return participant_inn;
		}
		public void setDescription(Description description) {
			this.description = description;
		}
		public void setDoc_id(String doc_id) {
			this.doc_id = doc_id;
		}
		public void setDoc_type(String doc_type) {
			this.doc_type = doc_type;
		}
		public void setImportRequest(String importRequest) {
			this.importRequest = importRequest;
		}
		public void setOwner_inn(String owner_inn) {
			this.owner_inn = owner_inn;
		}
		public void setParticipant_inn(String participant_inn) {
			this.participant_inn = participant_inn;
		}
		public void setProducts(List<Product> products) {
			this.products = products;
		}
		public List<Product> getProducts() {
			return products;
		}
		private static class Description{
			public String participantInn;

			public String getParticipantInn() {
				return participantInn;
			}
			public void setParticipantInn(String participantInn) {
				this.participantInn = participantInn;
			}		
		}
	}
	private static class Product{
		public String certificate_document = null;
		public String certificate_document_date = null;
		public String certificate_document_number = null;
		public String owner_inn = "";
		public String producer_inn = "";
		public String production_date = "";
		public String tnved_code = "";
		public String uit_code = null;
		public String uitu_code = null;
		public void setCertificate_document(String certificate_document) {
			this.certificate_document = certificate_document;
		}
		public void setCertificate_document_date(String certificate_document_date) {
			this.certificate_document_date = certificate_document_date;
		}
		public void setCertificate_document_number(String certificate_document_number) {
			this.certificate_document_number = certificate_document_number;
		}
		public void setOwner_inn(String owner_inn) {
			this.owner_inn = owner_inn;
		}
		public void setProducer_inn(String producer_inn) {
			this.producer_inn = producer_inn;
		}
		public void setProduction_date(String production_date) {
			this.production_date = production_date;
		}
		public void setTnved_code(String tnved_code) {
			this.tnved_code = tnved_code;
		}
		public void setUit_code(String uit_code) {
			this.uit_code = uit_code;
		}
		public void setUitu_code(String uitu_code) {
			this.uitu_code = uitu_code;
		}
		
	}
	private static interface Document{
		
		public String getTypeOfDocument();
	}
	
	public synchronized void sendDoc(Object doc, String cert) {
		
	}	
}
