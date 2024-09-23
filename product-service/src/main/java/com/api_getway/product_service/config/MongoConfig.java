package com.api_getway.product_service.config;

import com.mongodb.ConnectionString;
import com.mongodb.MongoClientSettings;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.mongodb.core.MongoTemplate;

@Configuration
@RefreshScope
public class MongoConfig {

    @Value("${spring.data.mongodb.host}")
    private String host;

    @Value("${spring.data.mongodb.port}")
    private int port;

    @Value("${spring.data.mongodb.database}")
    private String database;

    @Value("${spring.data.mongodb.username}")
    private String username;

    @Value("${spring.data.mongodb.password}")
    private String password;

    @Value("${spring.data.mongodb.authentication-database}")
    private String authDatabase;

    @Bean
    @RefreshScope
    public MongoClient mongoClient() {
        String uri = String.format("mongodb://%s:%s@%s:%d/%s?authSource=%s",
                username, password, host, port, database, authDatabase);

        System.out.println("Connecting to MongoDB with URI: " + uri);

        ConnectionString connectionString = new ConnectionString(uri);
        MongoClientSettings settings = MongoClientSettings.builder()
                .applyConnectionString(connectionString)
                .build();
        return MongoClients.create(settings);
    }

    @Bean
    @RefreshScope
    public MongoTemplate mongoTemplate(MongoClient mongoClient) {
        return new MongoTemplate(mongoClient, database);
    }
}
