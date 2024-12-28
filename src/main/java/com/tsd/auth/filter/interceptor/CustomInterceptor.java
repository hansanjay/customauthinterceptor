package com.tsd.auth.filter.interceptor;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;
import org.tsd.sdk.response.APIResponse;
import org.tsd.sdk.response.AuthResponse;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tsd.auth.filter.service.CustomerAuthService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class CustomInterceptor implements HandlerInterceptor {
	
	@Autowired
    private CustomerAuthService customerAuthService;

    @Autowired
    private ObjectMapper mapper;

//    @Override
//    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
//        System.out.println("Interceptor triggered for URI: " + request.getRequestURI());
//        return true;
//    }
    
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        AuthResponse authResponse = customerAuthService.isAuthenticated(request);

        if (authResponse.isResult()) {
            return true;
        } else {
            // Set response status and content type
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");

            // Prepare the error response
            APIResponse apiResponse = new APIResponse(HttpServletResponse.SC_UNAUTHORIZED,"Authentication Failed",authResponse.getMessage());

            // Write the APIResponse as JSON
            response.getOutputStream().write(mapper.writeValueAsBytes(apiResponse));

            return false; // Stop further processing
        }
    }
    
    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response,
                    Object handler, ModelAndView modelAndView) throws Exception {
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response,
                         Object handler, Exception ex) throws Exception {
        if (ex != null) ex.printStackTrace();
    }
}
	