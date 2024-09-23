package com.api_getway.product_service.feature.filemetadata;

import com.api_getway.product_service.domain.FileMetaData;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

public interface FileMetaDataRepository extends MongoRepository<FileMetaData, Long> {

    Optional<FileMetaData> findByFileName(String fileName);

    boolean existsByFileName(String fileName);
}
