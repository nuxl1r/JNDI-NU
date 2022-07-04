package com.feihong.ldap.utils;

import com.feihong.ldap.template.*;
import net.jodah.expiringmap.ExpirationPolicy;
import net.jodah.expiringmap.ExpiringMap;
import java.util.concurrent.TimeUnit;

public class Cache {
    private static ExpiringMap<String, byte[]> map = ExpiringMap.builder()
            .maxSize(1000)
            .expiration(30, TimeUnit.SECONDS)
            .variableExpiration()
            .expirationPolicy(ExpirationPolicy.CREATED)
            .build();

    static{
        try {
            //过期时间100年，永不过期的简单方法
            map.put("TomcatEchoTemplate", Util.getClassBytes(TomcatEchoTemplate.class), 365 * 100, TimeUnit.DAYS);
            map.put("SpringEchoTemplate", Util.getClassBytes(SpringEchoTemplate.class), 365 * 100, TimeUnit.DAYS);
            map.put("WeblogicEchoTemplate", Util.getClassBytes(WeblogicEchoTemplate.class), 365 * 100, TimeUnit.DAYS);
            map.put("TomcatMemshellTemplate1", Util.getClassBytes(TomcatMemshellTemplate1.class), 365 * 100, TimeUnit.DAYS);
            map.put("TomcatMemshellTemplate2", Util.getClassBytes(TomcatMemshellTemplate2.class), 365 * 100, TimeUnit.DAYS);
            map.put("JettyMemshellTemplate", Util.getClassBytes(JettyMemshellTemplate.class), 365 * 100, TimeUnit.DAYS);
            map.put("WeblogicMemshellTemplate1", Util.getClassBytes(WeblogicMemshellTemplate1.class), 365 * 100, TimeUnit.DAYS);
            map.put("WeblogicMemshellTemplate2", Util.getClassBytes(WeblogicMemshellTemplate2.class), 365 * 100, TimeUnit.DAYS);
            map.put("BehinderFilter", Util.getClassBytes(BehinderFilter.class), 365 * 100, TimeUnit.DAYS);
            map.put("JBossMemshellTemplate", Util.getClassBytes(JBossMemshellTemplate.class), 365 * 100, TimeUnit.DAYS);
            map.put("WebsphereMemshellTemplate", Util.getClassBytes(WebsphereMemshellTemplate.class), 365 * 100, TimeUnit.DAYS);
            map.put("SpringMemshellTemplate", Util.getClassBytes(SpringMemshellTemplate.class), 365 * 100, TimeUnit.DAYS);
            map.put("isOK", Util.getClassBytes(isOK.class), 365 * 100, TimeUnit.DAYS);
            //测试添加到cache中
            map.put("isSuccess",Util.getClassBytes(isSuccess.class),365 * 100, TimeUnit.DAYS);
            map.put("GodzillaFilter",Util.getClassBytes(GodzillaFilter.class),365 * 100, TimeUnit.DAYS);
            map.put("JettyBehinderFilter",Util.getClassBytes(JettyBehinderFilter.class),365 * 100, TimeUnit.DAYS);
            map.put("Meterpreter",ClassByteChange.update(Meterpreter.class),365 * 100, TimeUnit.DAYS);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static byte[] get(String key){
        return map.get(key);
    }

    public static void set(String key, byte[] bytes){
        map.put(key, bytes);
    }

    public static boolean contains(String key){
        return map.containsKey(key);
    }

    public static void remove(String key){
        map.remove(key);
    }
}
