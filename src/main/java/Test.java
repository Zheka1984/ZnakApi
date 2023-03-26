import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import ch.qos.logback.core.util.TimeUtil;

public class Test {

	public static void main(String[] args) throws Exception {
		CrptApi ca = new CrptApi(TimeUnit.MINUTES, 1);
		CrptApi.VvodVOborot vvo = new CrptApi.VvodVOborot();
		CrptApi.VvodVOborot.Description desc = new CrptApi.VvodVOborot.Description();
		vvo.setDescription(desc);
		vvo.setDoc_id("15240");
		vvo.setDoc_type("тестовый документ");
		vvo.setImportRequest("нет");
		vvo.setOwner_inn("615290158489");
		vvo.setParticipant_inn("25897871552");
		CrptApi.Product prod1 = new CrptApi.Product();
		CrptApi.Product prod2 = new CrptApi.Product();
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
		List<CrptApi.Product> list = new ArrayList<>();
		list.add(prod1); list.add(prod2);
		vvo.setProducts(list);
        ca.sendDoc(vvo, "37dff89c2-cbdb-e17c-e51a-08f215f017e");
        ca.sendDoc(vvo, "37dff89c2-cbdb-e17c-e51a-08f215f017e");
	}
}
