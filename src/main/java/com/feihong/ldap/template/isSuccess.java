package com.feihong.ldap.template;

public class isSuccess {
    public String test = "impl run success";
    static {
        System.out.println("static run success");
        isSuccess x=new isSuccess();
        System.out.println(x.getTest());
    }

    public String getTest() {
        return test;
    }

    public String toString() {
        System.out.println("toString run success");
        return "";
    }
}
