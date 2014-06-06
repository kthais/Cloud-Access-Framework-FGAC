package pdp.identity_federation.picketlink;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;

import org.jboss.security.xacml.core.model.context.ActionType;
import org.jboss.security.xacml.core.model.context.EnvironmentType;
import org.jboss.security.xacml.core.model.context.RequestType;
import org.jboss.security.xacml.core.model.context.ResourceType;
import org.jboss.security.xacml.core.model.context.SubjectType;
import org.jboss.security.xacml.factories.RequestAttributeFactory;
import org.picketlink.identity.federation.api.soap.SOAPSAMLXACML;
import org.picketlink.identity.federation.api.soap.SOAPSAMLXACML.Result;

/*
 * Policy Target Mis-Match so policy Not-Applicable
 */

public class PEPRequestCreator {

	//private boolean debug = "true".equals(System.getProperty("debug", "true"));
	private String endpoint = "http://localhost:11345/pdp/SOAPServlet";

	public static void main(String[] args) throws Exception{
		PEPRequestCreator  test = new PEPRequestCreator();
		test.testAccess("Administration","Administrator","None","Guest","Past Paper",
				"None","None","Write","09:01:00","None");
		
	}
	public String testAccess(String s1, String s2, String s3, String s4,
			String r1, String r2, String r3, String a1, String e1, String e2)
			throws Exception {
		// Check PERMIT condition
		RequestType xacmlRequest = requestCreator(s1, s2, s3, s4, r1, r2, r3,
				a1, e1, e2);
		SOAPSAMLXACML soapSAMLXACML = new SOAPSAMLXACML();

		Result result = soapSAMLXACML.send(endpoint, "PEP", xacmlRequest);

		return result.getDecision().toString();

	}

	public static RequestType requestCreator(String s1, String s2, String s3,
			String s4, String r1, String r2, String r3, String a1, String e1,
			String e2) throws Exception {

		// Create a subject type
		SubjectType subject = new SubjectType();

		subject.getAttribute().add(
				RequestAttributeFactory.createStringAttributeType(
						"urn:oasis:names:tc:xacml:1.0:subject:group-zero",
						"PEP", s1));

		subject.getAttribute().add(
				RequestAttributeFactory.createStringAttributeType(
						"urn:oasis:names:tc:xacml:1.0:subject:group-one",
						"PEP", s2));

		subject.getAttribute().add(
				RequestAttributeFactory.createStringAttributeType(
						"urn:oasis:names:tc:xacml:1.0:subject:group-two",
						"PEP", s3));

		subject.getAttribute().add(
				RequestAttributeFactory.createStringAttributeType(
						"urn:oasis:names:tc:xacml:1.0:subject:access", "PEP",
						s4));

		// Create a resource type
		ResourceType resourceType = new ResourceType();

		resourceType.getAttribute().add(
				RequestAttributeFactory.createStringAttributeType(
						"urn:oasis:names:tc:xacml:1.0:resource:resource-id",
						"PEP", r1));

		resourceType.getAttribute().add(
				RequestAttributeFactory.createStringAttributeType(
						"urn:oasis:names:tc:xacml:1.0:resource:author", "PEP",
						r2));

		resourceType.getAttribute().add(
				RequestAttributeFactory.createStringAttributeType(
						"urn:oasis:names:tc:xacml:1.0:resource:requestor",
						"PEP", r3));

		// Create an action type
		ActionType actionType = new ActionType();
		actionType.getAttribute().add(
				RequestAttributeFactory.createStringAttributeType(
						"urn:oasis:names:tc:xacml:1.0:action:action-id", "PEP",
						a1));

		EnvironmentType environmentType = new EnvironmentType();

		environmentType
				.getAttribute()
				.add(RequestAttributeFactory
						.createTimeAttributeType(
								"urn:oasis:names:tc:xacml:1.0:environment:current-time",
								"PEP", getXMLTime(e1)));

		environmentType.getAttribute().add(
				RequestAttributeFactory.createDateTimeAttributeType(
						"urn:oasis:names:tc:xacml:1.0:environment:timeCreated",
						"PEP", getXMLTime("2013-04-14T10:38:28Z")));

		// Create a Request Type
		RequestType requestType = new RequestType();

		requestType.getResource().add(resourceType);
		requestType.getSubject().add(subject);
		requestType.setAction(actionType);
		requestType.setEnvironment(environmentType);

		return requestType;
	}

	private static XMLGregorianCalendar getXMLTime(String time) {
		DatatypeFactory dtf;
		try {
			dtf = DatatypeFactory.newInstance();
		} catch (DatatypeConfigurationException e) {
			throw new RuntimeException(e);
		}
		return dtf.newXMLGregorianCalendar(time);
	}
}
