package com.api_getway.product_service.feature.product;

import com.api_getway.product_service.feature.product.dto.ProductRequest;
import com.api_getway.product_service.feature.product.dto.ProductResponse;
import com.api_getway.product_service.feature.product.dto.ProductUpdateRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/products")
public class ProductController {

    private final ProductService productService;

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasAnyAuthority('SCOPE_openid')")
    public void createProduct(@Valid @RequestBody ProductRequest productRequest) {

        productService.createProduct(productRequest);
    }

    @GetMapping
    @PreAuthorize("hasAnyAuthority('SCOPE_openid')")
    public Page<ProductResponse> getAllProducts(
            @RequestParam(defaultValue = "0") int pageNumber,
            @RequestParam(defaultValue = "25") int pageSize) {

        return productService.getAllProducts(pageNumber, pageSize);
    }

    @GetMapping("/{id}")
//    @PreAuthorize("hasAnyAuthority('SCOPE_openid')")
    public ProductResponse getProductById(@PathVariable String id) {

        return productService.getProductById(id);
    }

    @PatchMapping("/{id}")
    @PreAuthorize("hasAnyAuthority('SCOPE_openid')")
    public ProductResponse updateProductById(@PathVariable String id,
                                               @Valid @RequestBody ProductUpdateRequest productUpdateRequest) {

        return productService.updateProductById(id, productUpdateRequest);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAnyAuthority('SCOPE_openid')")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deleteProductById(@PathVariable String id) {

        productService.deleteProductById(id);
    }

    @GetMapping("/public")
    public String getProductPublic() {

        return "this is public";
    }

}
