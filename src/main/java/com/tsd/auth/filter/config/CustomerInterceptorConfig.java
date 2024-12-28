package com.tsd.auth.filter.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import com.tsd.auth.filter.interceptor.CustomInterceptor;

@Configuration
public class CustomerInterceptorConfig implements WebMvcConfigurer {

    @Autowired
    CustomInterceptor customInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(customInterceptor).addPathPatterns("/c/customer/profile");
        registry.addInterceptor(customInterceptor).addPathPatterns("/c/agent/profile");
    }
}