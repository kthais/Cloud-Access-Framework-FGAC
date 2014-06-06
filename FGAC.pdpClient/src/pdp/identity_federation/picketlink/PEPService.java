package pdp.identity_federation.picketlink;

public class PEPService {

	public String sendRequest(String s1, String s2, String s3, String s4,
			String r1, String r2, String r3, String a1, String e1, String e2)
			throws Exception {
		PEPRequestCreator request = new PEPRequestCreator();
		String temp = request
				.testAccess(s1, s2, s3, s4, r1, r2, r3, a1, e1, e2);
		System.out.println("--------->" + temp);
		return temp;
	}
}
