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
 * A string validator class used to validate various XACML Data types.
 * 
 * @author Umair Asghar <10beseuasghar@seecs.edu.pk>
 * @version 1.0
 */
public class StringValidator implements Validator {

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
	 * Function to check for the valid data for a selected data type
	 */
	public void validate(FacesContext context, UIComponent component,
			Object value) throws ValidatorException {

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
}
