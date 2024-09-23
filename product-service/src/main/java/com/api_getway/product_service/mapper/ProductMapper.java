package com.api_getway.product_service.mapper;

import com.api_getway.product_service.domain.Product;
import com.api_getway.product_service.feature.product.dto.ProductRequest;
import com.api_getway.product_service.feature.product.dto.ProductResponse;
import com.api_getway.product_service.feature.product.dto.ProductUpdateRequest;
import com.api_getway.product_service.utils.MediaUtil;
import org.mapstruct.*;

@Mapper(componentModel = "spring")
public interface ProductMapper {

    Product fromRequest(ProductRequest videoRequest);

    @Mapping(source = "image",target = "image",qualifiedByName = "getImageUrl")
    ProductResponse toResponse(Product product);

    @BeanMapping(nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE)
    void updateProductFromRequest(@MappingTarget Product product, ProductUpdateRequest productUpdateRequest);

    @Named("getImageUrl")
    default String getLogoUrl(String image) {

        if (image != null && !image.trim().isEmpty()) {
            return MediaUtil.getUrl(image);
        } else {
            return null;
        }
    }
}
