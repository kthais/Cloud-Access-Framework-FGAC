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

import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.faces.convert.Converter;
import javax.faces.convert.FacesConverter;

/**
 * A trimmer class used to trim leading and trailing spaces in a string value.
 * 
 * @author Umair Asghar <10beseuasghar@seecs.edu.pk>
 * @version 1.0
 */

@FacesConverter(forClass = String.class)
public class StringTrimmer implements Converter {

	/**
	 * Function to get trim the leading and trailing spaces in passed values
	 */
	@Override
	public Object getAsObject(FacesContext context, UIComponent component,
			String value) {
		return value != null ? value.trim() : null;
	}

	/**
	 * Function to get String Value from Text field in GUI
	 */

	@Override
	public String getAsString(FacesContext context, UIComponent component,
			Object value) {
		return (String) value;
	}

}
