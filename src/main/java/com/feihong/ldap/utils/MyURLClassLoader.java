package com.feihong.ldap.utils;

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;

public class MyURLClassLoader {
    private URLClassLoader classLoader;

    public MyURLClassLoader(String jarName){
        try{
            classLoader = getURLClassLoader(jarName);
        }catch(MalformedURLException e){
            e.printStackTrace();
        }
    }

    public Class loadClass(String className) {
        try{
            //由于我项目中已经有了 commons-beanutils:1.9.4，如果使用 loadClass 方法，加载的是项目 ClassPath 下的 commons-beanutils
            //为了避免这种情况，所以调用了 findClass 方法
            Method method = URLClassLoader.class.getDeclaredMethod("findClass", new Class[]{String.class});
            method.setAccessible(true);
            Class clazz = (Class) method.invoke(this.classLoader, new Object[]{className});
            return clazz;
        } catch (NoSuchMethodException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        } catch (InvocationTargetException e) {
            e.printStackTrace();
        }

        return null;
    }


    private URLClassLoader getURLClassLoader(String jarName) throws MalformedURLException {
        String path = System.getProperty("user.dir") + File.separator + "lib" + File.separator + jarName;
        File file = new File(path);
        URL url = file.toURI().toURL();
        URLClassLoader urlClassLoader = new URLClassLoader(new URL[]{url});
        return urlClassLoader;
    }
}
