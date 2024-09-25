//package com.api_getway.spring_cloud_getway.config;
//
//import org.springframework.context.annotation.Configuration;
//import org.springframework.web.reactive.config.CorsRegistry;
//
//@Configuration
//public class CoreConfig implements WebMvcConfigurer {
//
//    @Override
//    public void addCorsMappings(CorsRegistry registry) {
//        registry.addMapping("/**") // Allow CORS on all paths
//                .allowedOrigins("http://localhost:3000") // Allow only requests from this origin
//                .allowedMethods("GET", "POST", "PUT", "DELETE") // Allow specific HTTP methods
//                .allowedHeaders("*") // Allow all headers
//                .allowCredentials(true);
//    }
//}
