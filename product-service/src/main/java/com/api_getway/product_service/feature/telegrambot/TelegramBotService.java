package com.api_getway.product_service.feature.telegrambot;


import com.api_getway.product_service.domain.FileMetaData;
import com.api_getway.product_service.domain.Product;

public interface TelegramBotService {
    void sendProductResponse(Product product);

    void sendFileUpload(FileMetaData file);
}
