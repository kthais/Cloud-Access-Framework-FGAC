package pdp.identity_federation.picketlink;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Scanner;

public class PolicyRepositoryConfig {
	public static void main(String[] args) throws IOException {

		String str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +"\n"
				+ "<PolicySet xmlns=\"urn:oasis:names:tc:xacml:2.0:policy:schema:os\""
				+ " PolicyCombiningAlgId=\"urn:oasis:names:tc:xacml:1.0:policy-combining-algorithm:permit-overrides\""
				+ " PolicySetId=\"Test\" Version=\"2.0\">" + "\n" + "<Target />"+"\n";

		String policySetString ="";
		String policyString = "";
		File directory = new File("src/policyRepository/");
		File files[] = directory.listFiles();
		for (File f : files) {
			System.out.println(f.getName());
			FileReader fr = new FileReader(f);
			BufferedReader br = new BufferedReader(fr);

			while ((policySetString = br.readLine()) != null) {
				System.out.println(policySetString);
				if (!policySetString.contains("?xml")) {
					policyString= policyString.concat(policySetString + "\n");
				}
			}
			br.close();
			
		}
		
 
		str = str + policyString + "</PolicySet>";

		FileWriter fri = new FileWriter("src/policySet.xml");
		BufferedWriter bfi = new BufferedWriter(fri);

		bfi.write(String.valueOf(str));
		bfi.newLine();

		bfi.close();

	}
}
