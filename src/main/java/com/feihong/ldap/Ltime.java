package com.feihong.ldap;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

public class Ltime {
    public static String getLocalTime(){
        Date d = new Date();
        DateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        return sdf.format(d);
    }
}
