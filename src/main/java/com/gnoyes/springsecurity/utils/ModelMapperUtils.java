package com.gnoyes.springsecurity.utils;

import org.modelmapper.ModelMapper;

public class ModelMapperUtils {
    private static ModelMapper modelMapper;

    public static ModelMapper getModelMapper(){
        if(modelMapper == null){
            modelMapper = new ModelMapper();
        }
        return modelMapper;
    }

}
