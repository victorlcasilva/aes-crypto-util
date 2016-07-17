package com.the008.app.cryptoutil.util;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.apache.log4j.Logger;

public class DateUtil {

    private static final String DATE_PATTERN_DMY = "dd/MM/yyyy";
    private static Logger log = Logger.getLogger(DateUtil.class);
    
    public static Date getDate(String date){
        Date retorno = null;
        try{
            SimpleDateFormat sdf = new SimpleDateFormat(DATE_PATTERN_DMY);
            retorno = sdf.parse(date);
        }catch(ParseException pe){
            log.error("Error parsing data: "+pe.getMessage(), pe);
        }
        return retorno;
    }
    
    public static String formatDate(Date date){
        return (new SimpleDateFormat(DATE_PATTERN_DMY)).format(date);
    }
    
}
