/*---------------------------------------------------------------
*  Copyright 2015 by the Radiological Society of North America
*
*  This source software is released under the terms of the
*  RSNA Public License (http://mirc.rsna.org/rsnapubliclicense.pdf)
*----------------------------------------------------------------*/

package org.rsna.util;

import java.io.*;
import java.util.Hashtable;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.zip.*;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

public class ExcelWorksheet {
	
	Hashtable<String,String> cells;
	Hashtable<Integer,String> shared;
	String name;
	int lastRow = 0;
	String lastColumn = "";

	/**
	 * Constructor: get a worksheet from an xlsx file.
	 * @param file the Excel spreadsheet file (must be an xlsx file)
	 * @param worksheet name (e.g., "sheet.xml", case-sensitive)
	 * @throws Exception if the worksheet cannot be obtained.
	 */
	public ExcelWorksheet(File file, String worksheet) throws Exception {
		this.name = worksheet;
		ZipFile zipFile = new ZipFile(file);
		String stext = getEntryText(zipFile, "xl/sharedStrings.xml");
		String sheet = getEntryText(zipFile, "xl/worksheets/"+worksheet);
		zipFile.close();
		
		Document sdoc = XmlUtil.getDocument(stext);
		Element sroot = sdoc.getDocumentElement();
		shared = new Hashtable<Integer,String>();
		NodeList texts = sroot.getElementsByTagName("si");
		for (int i=0; i<texts.getLength(); i++) {
			Element si = (Element)texts.item(i);
			NodeList tList = si.getElementsByTagName("t");
			String t = (tList.getLength() > 0) ? tList.item(0).getTextContent().trim() : "";
			shared.put( new Integer(i), t);
		}		
		
		Document doc = XmlUtil.getDocument(sheet);
		Element root = doc.getDocumentElement();
		cells = new Hashtable<String,String>();
		NodeList cellList = root.getElementsByTagName("c");
		for (int i=0; i<cellList.getLength(); i++) {
			Element c = (Element)cellList.item(i);
			String r = c.getAttribute("r");
			
			int row = StringUtil.getInt( r.replaceAll("[A-Z]", "") );
			if (row > lastRow) lastRow = row;
			String column = r.replaceAll("[0-9]","");
			if (column.compareTo(lastColumn) > 0) lastColumn = column;
			
			String t = c.getAttribute("t");
			NodeList vList = c.getElementsByTagName("v");
			String v = (vList.getLength() > 0) ? vList.item(0).getTextContent().trim() : "";
			if (t.equals("s")) {
				try { v = shared.get( new Integer(v) ); }
				catch (Exception ignore) { }
			}
			cells.put(r, v);
		}
	}
	
	/**
	 * Get the name of this worksheet.
	 * @return the name of this worksheet
	 */
	public String getName() {
		return name;
	}
	
	/**
	 * Get the number of cells in this worksheet.
	 * @return the number of cells in this worksheet
	 */
	public int getSize() {
		return cells.size();
	}

	/**
	 * Get the last row number in this worksheet.
	 * @return the last row number in this worksheet
	 */
	public int getLastRow() {
		return lastRow;
	}

	/**
	 * Get the last column identifier in this worksheet.
	 * @return the last column identifier in this worksheet
	 */
	public String getLastColumn() {
		return lastColumn;
	}

	/**
	 * Get the list of worksheet names in an xlsx file.
	 * @param file the xlsx file
	 * @return the list of worksheet names.
	 */
	public static LinkedList<String> getWorksheetNames(File file) {
		LinkedList<String> list = new LinkedList<String>();
		try {
			ZipFile zipFile = new ZipFile(file);
			ZipEntry ze;
			Enumeration<? extends ZipEntry> e = zipFile.entries();
			while (e.hasMoreElements()) {
				ze = e.nextElement();
				if (!ze.isDirectory()) {
					String name = ze.getName();
					if (name.startsWith("xl/worksheets/") && name.endsWith(".xml")) {
						File sheet = new File(ze.getName());
						list.add( sheet.getName() );
					}
				}
			}
			zipFile.close();
		}
		catch (Exception ex) { }
		return list;
	}
	
	/**
	 * Search a row and return the column identifier (e.g., "A", "B", etc.) of the
	 * first cell containing the specified text. Note: this method only searches the first
	 * 26 columns ("A" through "Z").
	 * @param row the row to search
	 * @param text the text to match (case-sensitive)
	 * @return the column identifier, or the empty string if no cell matches the
	 * specified text.
	 */
	public String findColumn(int row, String text) {
		for (int i=0; i<26; i++) {
			String col = Character.toString( (char)('A'+i) );
			String cell = getCell( col + row );
			if ((cell != null) && cell.equals(text)) return col;
		}
		return "";
	}

	private String getEntryText(ZipFile zipFile, String name) throws Exception {
		ZipEntry entry = zipFile.getEntry(name);
		StringWriter sw = new StringWriter();
		BufferedReader in = null;
		in = new BufferedReader(
					new InputStreamReader(zipFile.getInputStream(entry), FileUtil.utf8));
		int n = 0;
		char[] cbuf = new char[1024];
		while ((n = in.read(cbuf, 0, cbuf.length)) != -1) sw.write(cbuf, 0, n);
		in.close();
		return sw.toString();
	}
	
	/**
	 * Get the contents of a cell
	 * @param adrs the column and row of the cell in the standard format (e.g, C41).
	 * @return the contents of the specified cell.
	 */
	public String getCell(String adrs) {
		String value = cells.get(adrs);
		return (value != null) ? value : "";
	}
}