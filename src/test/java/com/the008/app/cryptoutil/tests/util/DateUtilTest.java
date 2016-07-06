package com.the008.app.cryptoutil.tests.util;

import java.util.Date;

import org.apache.log4j.Logger;
import org.junit.Assert;
import org.junit.Test;

import com.the008.app.cryptoutil.util.DateUtil;

public class DateUtilTest {

    private Logger log = Logger.getLogger(getClass());
    private String date = "15/05/1989";
    
    @Test
    public void test01_GeneratePassword(){
        log.info("Testing Date Format using test date "+date);
        Date dt1 = DateUtil.getDate(date);
        String dt2 = DateUtil.formatDate(dt1);
        Assert.assertEquals("The formatted date should be "+date, dt2, date);
    }
    
}
