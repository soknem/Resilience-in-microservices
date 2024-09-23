package com.api_getway.product_service.feature.product;

import com.api_getway.product_service.feature.product.dto.ProductRequest;
import com.api_getway.product_service.feature.product.dto.ProductResponse;
import com.api_getway.product_service.feature.product.dto.ProductUpdateRequest;
import org.springframework.data.domain.Page;

public interface ProductService {

    void createProduct(ProductRequest productRequest);

    Page<ProductResponse> getAllProducts(int pageNumber, int pageSize);

    ProductResponse getProductById(String id);

    ProductResponse updateProductById(String id, ProductUpdateRequest productUpdateRequest);

    void deleteProductById(String id);


}
