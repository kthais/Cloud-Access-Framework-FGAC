/******************************************************************************
 * Project:    Extensible Access Control Framework for Cloud based Applications.
 *                     http://ais.seecs.nust.edu.pk/project/ 
 * Developed by: KTH- Applied Information Security Lab (AIS), 
 *                       NUST-SEECS, H-12 Campus, 
 *                       Islamabad, Pakistan. 
 *                       www.ais.seecs.nust.edu.pk
 * Funded by: National ICT R&D Fund, Ministry of Information Technology & Telecom,
 *                  http://www.ictrdf.org.pk/
 * Copyright (c) 2013-2015 All Rights Reserved, AIS-SEECS NUST & National ICT R&D Fund

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy and/or modify the Software, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software. 

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *****************************************************************************/

package com.aislab.accesscontrol.core.ui.validator;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.faces.application.FacesMessage;
import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.faces.validator.Validator;
import javax.faces.validator.ValidatorException;

/**
 * A validator class used to validate various XACML Data types.
 * 
 * @author Umair Asghar <10beseuasghar@seecs.edu.pk>
 * @version 1.0
 */
public class DataTypeValidator implements Validator {

	/**
	 * A string variable used to define Regex pattern of Integer data type
	 */
	private final static String INTEGER_PATTERN = "[-+]?[1-9][0-9]*|0";

	/**
	 * A pattern type variable used to compile the Regex pattern of Integer data
	 * type
	 */
	private final static Pattern INTEGER_COMPILED_PATTERN = Pattern
			.compile(INTEGER_PATTERN);

	/**
	 * A string variable used to define Regex pattern of String data type
	 */
	private final static String STRING_PATTERN = "(([a-zA-Z(\\[!^|])+([a-zA-Z0-9'_,\\-\"\\.\\(\\)\\[!^?*$| ])*)+";

	/**
	 * A pattern type variable used to compile the Regex pattern of STRING data
	 * type
	 */
	private final static Pattern STRING_COMPILED_PATTERN = Pattern
			.compile(STRING_PATTERN);

	/**
	 * A string variable used to define Regex pattern of ANYURI data type
	 */
	private final static String ANYURI_PATTERN = "\\b(https?|ftp|file)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|]";

	/**
	 * A pattern type variable used to compile the Regex pattern of ANYURI data
	 * type
	 */
	private final static Pattern ANYURI_COMPILED_PATTERN = Pattern
			.compile(ANYURI_PATTERN);

	/**
	 * A string variable used to define Regex pattern of DOUBLE data type
	 */
	private final static String DOUBLE_PATTERN = "[-+]?[0-9][1-9]*[.][0-9]+";

	/**
	 * A pattern type variable used to compile the Regex pattern of DOUBLE data
	 * type
	 */
	private final static Pattern DOUBLE_COMPILED_PATTERN = Pattern
			.compile(DOUBLE_PATTERN);

	/**
	 * A string variable used to define Regex pattern of TIME data type
	 */
	private final static String TIME_PATTERN = "(([0][0-9]|1[0-9]|2[0-3])[:][0-5][0-9][:][0-5][0-9]){1}([-+]([0][0-9]|1[0-9]|2[0-3])[:][0-5][0-9])?";

	/**
	 * A pattern type variable used to compile the Regex pattern of TIME data
	 * type
	 */
	private final static Pattern TIME_COMPILED_PATTERN = Pattern
			.compile(TIME_PATTERN);

	/**
	 * A string variable used to define Regex pattern of DATE data type
	 */
	private final static String DATE_PATTERN = "([0-9][0-9][0-9][0-9][-]([0][0-9]|1[1-2])-([0][0-9]|1[0-9]|2[0-9]|3[0-1])){1}([-+]([0][0-9]|1[0-9]|2[0-3])[:][0-5][0-9])?";

	/**
	 * A pattern type variable used to compile the Regex pattern of DATE data
	 * type
	 */
	private final static Pattern DATE_COMPILED_PATTERN = Pattern
			.compile(DATE_PATTERN);

	/**
	 * A string variable used to define Regex pattern of DATETIME data type
	 */
	private final static String DATETIME_PATTERN = "([0-9][0-9][0-9][0-9][-]([0][0-9]|1[1-2])-([0][0-9]|1[0-9]|2[0-9]|3[0-1])[T]([0][0-9]|1[0-9]|2[0-3])[:][0-5][0-9][:][0-5][0-9]){1}([-+]([0][0-9]|1[0-9]|2[0-3])[:][0-5][0-9])?";

	/**
	 * A pattern type variable used to compile the Regex pattern of DATETIME
	 * data type
	 */
	private final static Pattern DATETIME_COMPILED_PATTERN = Pattern
			.compile(DATETIME_PATTERN);

	/**
	 * A string variable used to define Regex pattern of DAYTIMEDURATION data
	 * type
	 */
	private final static String DAYTIMEDURATION_PATTERN = "(-)?P(\\d+D)?(T(\\d+H)?(\\d+M)?(\\d+(.\\d+)?S)?)?";

	/**
	 * A pattern type variable used to compile the Regex pattern of
	 * DAYTIMEDURATION data type
	 */
	private final static Pattern DAYTIMEDURATION_COMPILED_PATTERN = Pattern
			.compile(DAYTIMEDURATION_PATTERN);

	/**
	 * A string variable used to define Regex pattern of HEXBINARY data type
	 */
	private final static String HEXBINARY_PATTERN = "([0-9a-fA-F]{2})*";

	/**
	 * A pattern type variable used to compile the Regex pattern of HEXBINARY
	 * data type
	 */
	private final static Pattern HEXBINARY_COMPILED_PATTERN = Pattern
			.compile(HEXBINARY_PATTERN);

	/**
	 * A string variable used to define Regex pattern of BASE64BINARY data type
	 */
	private final static String BASE64BINARY_PATTERN = "(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})";

	/**
	 * A pattern type variable used to compile the Regex pattern of BASE64BINARY
	 * data type
	 */
	private final static Pattern BASE64BINARY_COMPILED_PATTERN = Pattern
			.compile(BASE64BINARY_PATTERN);

	/**
	 * A string variable used to define Regex pattern of RFC822NAME data type
	 */
	private final static String RFC822NAME_PATTERN = "^[_A-Za-z0-9-\\+]+(\\.[_A-Za-z0-9-]+)*@[A-Za-z0-9-]+(\\.[A-Za-z0-9]+)*(\\.[A-Za-z]{2,})$";

	/**
	 * A pattern type variable used to compile the Regex pattern of RFC822NAME
	 * data type
	 */
	private final static Pattern RFC822NAME_COMPILED_PATTERN = Pattern
			.compile(RFC822NAME_PATTERN);

	/********************************
	 * String X.500 AttributeType CN commonName L localityName ST
	 * stateOrProvinceName O organizationName OU organizationalUnitName C
	 * countryName STREET streetAddress DC domainComponent UID userid
	 *******************************/

	/**
	 * A string variable used to define Regex pattern of X500NAME data type
	 */
	private final static String X500NAME_PATTERN = "([A-Za-z ]*)=([A-Za-z0-9: ]*)[,]?";

	/**
	 * A pattern type variable used to compile the Regex pattern of X500NAME
	 * data type
	 */
	private final static Pattern X500NAME_COMPILED_PATTERN = Pattern
			.compile(X500NAME_PATTERN);

	/**
	 * A string variable used to define Regex pattern of IPv4ADDRESS data type
	 */
	private final static String IPv4ADDRESS_PATTERN = "^(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)(\\.(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)){3}$";

	/**
	 * A pattern type variable used to compile the Regex pattern of IPv4ADDRESS
	 * data type
	 */
	private final static Pattern IPv4ADDRESS_COMPILED_PATTERN = Pattern
			.compile(IPv4ADDRESS_PATTERN);

	/**
	 * A string variable used to define Regex pattern of IPv6ADDRESS data type
	 */
	private final static String IPv6ADDRESS_PATTERN = "^((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)::((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)$";

	/**
	 * A pattern type variable used to compile the Regex pattern of IPv6ADDRESS
	 * data type
	 */
	private final static Pattern IPv6ADDRESS_COMPILED_PATTERN = Pattern
			.compile(IPv6ADDRESS_PATTERN);

	/**
	 * A string variable used to define Regex pattern of DNSNAME data type
	 */
	private final static String DNSNAME_PATTERN = "^[A-Za-z0-9]+(\\.[A-Za-z0-9-]+)*(\\.[A-Za-z]{2,})$";

	/**
	 * A pattern type variable used to compile the Regex pattern of DNSNAME data
	 * type
	 */
	private final static Pattern DNSNAME_COMPILED_PATTERN = Pattern
			.compile(DNSNAME_PATTERN);

	/**
	 * Function to check for the valid data for a selected data type
	 */

	public void validate(FacesContext context, UIComponent component,
			Object value) throws ValidatorException {

		String dataType = (String) component.getAttributes().get("item");

		if (dataType == null) {

			FacesMessage message = new FacesMessage();
			message.setSeverity(FacesMessage.SEVERITY_ERROR);
			message.setSummary("DataType must be selected.");
			message.setDetail("DataType must be selected.");
			throw new ValidatorException(message);
		}

		else if (dataType.equalsIgnoreCase("String")) {

			Matcher matcher = STRING_COMPILED_PATTERN.matcher((String) value);

			if (!matcher.matches()) {

				FacesMessage message = new FacesMessage();
				message.setSeverity(FacesMessage.SEVERITY_ERROR);
				message.setSummary("String is not valid.");
				message.setDetail("String is not valid.String can have following characters only"
						+ " a-zA-Z0-9'_,\\-\"\\.\\(\\)\\[!^?*$|  . e.g. "
						+ "New_Policy, Test1-Policy etc");
				throw new ValidatorException(message);
			}
		}

		else if (dataType.equalsIgnoreCase("Integer")) {

			Matcher matcher = INTEGER_COMPILED_PATTERN.matcher((String) value);

			if (!matcher.matches()) {

				FacesMessage message = new FacesMessage();
				message.setSeverity(FacesMessage.SEVERITY_ERROR);
				message.setSummary("Integer is not valid.");
				message.setDetail("Integer is not valid.Valid integer can only start with"
						+ " -/+ sign or with numbers only without any decimal point in between. e.g. "
						+ "+3, -1, 0 etc.");
				throw new ValidatorException(message);
			}
		}

		else if (dataType.equalsIgnoreCase("Boolean")) {

			if (!value.toString().equalsIgnoreCase("true")
					&& !value.toString().equalsIgnoreCase("false")) {

				FacesMessage message = new FacesMessage();
				message.setSeverity(FacesMessage.SEVERITY_ERROR);
				message.setSummary("Boolean Value required.");
				message.setDetail("Boolean value is not valid. Valid boolean values are True/False "
						+ "(case insensitive). e.g. tRue, FalsE, etc.");
				throw new ValidatorException(message);
			}
		}

		else if (dataType.equalsIgnoreCase("anyURI")) {

			Matcher matcher = ANYURI_COMPILED_PATTERN.matcher((String) value);

			if (!matcher.matches()) {

				FacesMessage message = new FacesMessage();
				message.setSeverity(FacesMessage.SEVERITY_ERROR);
				message.setSummary("URI is not valid.");
				message.setDetail("URI is not valid. Valid URI can start with https, "
						+ "file, ftp etc. and can be followed by "
						+ "a set of characters. e.g. https://www.google.com, ftp://file.txt");
				throw new ValidatorException(message);
			}
		}

		else if (dataType.equalsIgnoreCase("double")) {

			Matcher matcher = DOUBLE_COMPILED_PATTERN.matcher((String) value);

			if (!matcher.matches()) {

				FacesMessage message = new FacesMessage();
				message.setSeverity(FacesMessage.SEVERITY_ERROR);
				message.setSummary("Double is not valid.");
				message.setDetail("Double is not valid.Valid double value can only start with"
						+ " -/+ sign or with numbers only and must have a decimal point in between."
						+ " e.g. +3.0, -1.1, 0.0 etc.");
				throw new ValidatorException(message);
			}
		}

		else if (dataType.equalsIgnoreCase("time")) {

			Matcher matcher = TIME_COMPILED_PATTERN.matcher((String) value);

			if (!matcher.matches()) {

				FacesMessage message = new FacesMessage();
				message.setSeverity(FacesMessage.SEVERITY_ERROR);
				message.setSummary("Time is not valid.");
				message.setDetail("Time is not valid. Valid Time formats are HH:MM:SS"
						+ "or HH:MM:SS(-/+)HH:MM . e.g. 10:59:31, 10:59:31+05:00 etc.");
				throw new ValidatorException(message);
			}
		}

		else if (dataType.equalsIgnoreCase("date")) {

			Matcher matcher = DATE_COMPILED_PATTERN.matcher((String) value);

			if (!matcher.matches()) {

				FacesMessage message = new FacesMessage();
				message.setSeverity(FacesMessage.SEVERITY_ERROR);
				message.setSummary("Date is not valid.");
				message.setDetail("Date is not valid. Valid Date formats are YYYY-MM-DD"
						+ "or YYYY-MM-DD(-/+)HH:MM . e.g. 2014-05-09, 2014-05-09+05:00 etc.");
				throw new ValidatorException(message);
			}
		}

		else if (dataType.equalsIgnoreCase("datetime")) {

			Matcher matcher = DATETIME_COMPILED_PATTERN.matcher((String) value);

			if (!matcher.matches()) {

				FacesMessage message = new FacesMessage();
				message.setSeverity(FacesMessage.SEVERITY_ERROR);
				message.setSummary("Datetime is not valid.");
				message.setDetail("DateTime is not valid. Valid DateTime formats are YYYY-MM-DDTHH:MM:SS"
						+ "or YYYY-MM-DDTHH:MM:SS(-/+)HH:MM . e.g. 2014-05-09T11:01:50, "
						+ "2014-05-09T11:01:50+05:00 etc.");
				throw new ValidatorException(message);
			}
		}

		else if (dataType.equalsIgnoreCase("dayTimeDuration")) {

			Matcher matcher = DAYTIMEDURATION_COMPILED_PATTERN
					.matcher((String) value);

			if (!matcher.matches()) {

				FacesMessage message = new FacesMessage();
				message.setSeverity(FacesMessage.SEVERITY_ERROR);
				message.setSummary("DayTimeDuration is not valid.");
				message.setDetail("DayTimeDuration is not valid.Valid DayTimeDuration"
						+ " can have following characters P, D, T, H, M, S, - along with digits."
						+ "e.g. P1DT2H, PT20M, PT120M, P0D, -P60D, PT1M30.5S etc.	");
				throw new ValidatorException(message);
			}

			else if (value.toString().equals("P")
					| (value.toString().charAt(0) == 'P' && value.toString()
							.charAt(value.toString().length() - 1) == 'T')) {

				FacesMessage message = new FacesMessage();
				message.setSeverity(FacesMessage.SEVERITY_ERROR);
				message.setSummary("DayTimeDuration is not valid.");
				message.setDetail("DayTimeDuration is not valid.Valid DayTimeDuration"
						+ " can have following characters P, D, T, H, M, S, - along with digits."
						+ "e.g. P1DT2H, PT20M, PT120M, P0D, -P60D, PT1M30.5S etc.	");
				throw new ValidatorException(message);

			}
		}

		else if (dataType.equalsIgnoreCase("hexBinary")) {

			Matcher matcher = HEXBINARY_COMPILED_PATTERN
					.matcher((String) value);

			if (!matcher.matches()) {

				FacesMessage message = new FacesMessage();
				message.setSeverity(FacesMessage.SEVERITY_ERROR);
				message.setSummary("HexBinary is not valid.");
				message.setDetail("HexBinary is not valid.Valid hexBinary value can have"
						+ "Lowercase/uppercase letters A through F along with digits. Even number "
						+ "of characters are allowed. e.g. 0FB8, 0fb8 etc.");
				throw new ValidatorException(message);
			}
		}

		else if (dataType.equalsIgnoreCase("base64Binary")) {

			Matcher matcher = BASE64BINARY_COMPILED_PATTERN
					.matcher((String) value);

			if (!matcher.matches()) {

				FacesMessage message = new FacesMessage();
				message.setSeverity(FacesMessage.SEVERITY_ERROR);
				message.setSummary("Base64Binary is not valid.");
				message.setDetail("Base64Binary is not valid.Valid Base64Binary value can have"
						+ "letters A to Z (upper and lower case), digits 0 through 9, "
						+ "the plus sign (+), the slash (/), the equals sign (=) "
						+ "and whitespace characters. e.g. 0FB8, 0 FB8 0F+9, 0F+40A==	etc.");
				throw new ValidatorException(message);
			}
		}

		else if (dataType.equalsIgnoreCase("rfc822Name")) {

			Matcher matcher = RFC822NAME_COMPILED_PATTERN
					.matcher((String) value);

			if (!matcher.matches()) {

				FacesMessage message = new FacesMessage();
				message.setSeverity(FacesMessage.SEVERITY_ERROR);
				message.setSummary("RFC822Name is not valid.");
				message.setDetail("RFC822Name is not valid. Any valid Email address correspond to "
						+ "a valid rfc822 value. e.g. test@seecs.edu.pk, Test@gmail.com etc.");
				throw new ValidatorException(message);
			}
		}

		else if (dataType.equalsIgnoreCase("x500Name")) {

			Matcher matcher = X500NAME_COMPILED_PATTERN.matcher((String) value);

			if (!matcher.matches()) {

				FacesMessage message = new FacesMessage();
				message.setSeverity(FacesMessage.SEVERITY_ERROR);
				message.setSummary("X500NAME is not valid.");
				message.setDetail("X500NAME is not valid. Valid X500Name can start with an alphabet"
						+ "or an equals to (=) sign followed by any number characters. Multiple Values must be "
						+ "comma seperated ");
				throw new ValidatorException(message);
			}
		}

		else if (dataType.equalsIgnoreCase("ipv4Address")) {

			Matcher matcher = IPv4ADDRESS_COMPILED_PATTERN
					.matcher((String) value);

			if (!matcher.matches()) {

				FacesMessage message = new FacesMessage();
				message.setSeverity(FacesMessage.SEVERITY_ERROR);
				message.setSummary("IPv4ADDRESS is not valid.");
				message.setDetail("IPv4ADDRESS is not valid. Valid ipv4 addressformat is "
						+ " x . x . x . x where x is called an octet and must be a decimal "
						+ "value between 0 and 255. e.g. 1.2.3.4, 01.102.103.104 etc.");
				throw new ValidatorException(message);
			}
		}

		else if (dataType.equalsIgnoreCase("ipv6Address")) {

			Matcher matcher = IPv6ADDRESS_COMPILED_PATTERN
					.matcher((String) value);

			if (!matcher.matches()) {

				FacesMessage message = new FacesMessage();
				message.setSeverity(FacesMessage.SEVERITY_ERROR);
				message.setSummary("IPv6ADDRESS is not valid.");
				message.setDetail("IPv6ADDRESS is not valid. Valid ipv6 addressformat is "
						+ "  y : y : y : y : y : y : y : y where y is called a segment and "
						+ "can be any hexadecimal value between 0 and FFFF. "
						+ "e.g. 2001:db8:3333:4444:5555:6666:7777:8888, 2001:db8:: etc.");
				throw new ValidatorException(message);
			}
		}

		else if (dataType.equalsIgnoreCase("dnsName")) {

			Matcher matcher = DNSNAME_COMPILED_PATTERN.matcher((String) value);

			if (!matcher.matches()) {

				FacesMessage message = new FacesMessage();
				message.setSeverity(FacesMessage.SEVERITY_ERROR);
				message.setSummary("DNSNAME is not valid.");
				message.setDetail("DNSNAME is not valid.Valid DNS value can start with"
						+ " either an alphabet or digit followed by any number of alpabets,"
						+ "digits, dot and hyphen charactes. e.g. www.google.com, seecs.nust.edu.pk etc.");
				throw new ValidatorException(message);
			}
		}

		else if (dataType.equalsIgnoreCase("select datatype")) {

			FacesMessage message = new FacesMessage();
			message.setSeverity(FacesMessage.SEVERITY_ERROR);
			message.setSummary("Select DataType first.");
			message.setDetail("Select DataType first.");
			throw new ValidatorException(message);
		}
	}

}
