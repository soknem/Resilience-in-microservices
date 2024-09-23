package com.api_getway.product_service.feature.product;

import com.api_getway.product_service.domain.Product;
import org.springframework.data.mongodb.repository.MongoRepository;

public interface ProductRepository extends MongoRepository<Product,String> {
}
