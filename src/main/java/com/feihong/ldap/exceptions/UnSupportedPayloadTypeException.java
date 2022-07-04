package com.feihong.ldap.exceptions;

public class UnSupportedPayloadTypeException extends RuntimeException {
    public UnSupportedPayloadTypeException(){
        super();
    }
    public UnSupportedPayloadTypeException(String message){
        super(message);
    }
}
