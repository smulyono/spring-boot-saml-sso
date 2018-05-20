package com.github.smulyono.samldemo.metadata;

import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.saml2.metadata.provider.AbstractMetadataProvider;
import org.opensaml.xml.signature.P;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.security.saml.metadata.CachingMetadataManager;
import org.springframework.stereotype.Component;

@Component
@Setter
@Getter
@Slf4j
public class MetadataManagerProxy {
    CachingMetadataManager currentMetadata;

    public void reload() {
        log.info("Reloding metadata {}", currentMetadata);
        if (currentMetadata != null) {
            currentMetadata.getAvailableProviders().stream().forEach(i -> {
                if (i.getDelegate() instanceof AbstractMetadataProvider) {
                    i.setForceMetadataRevocationCheck(true);
//                    AbstractMetadataProvider provider = (AbstractMetadataProvider) i.getDelegate();
//                    provider.getMetadata().detach();
                }
            });
            currentMetadata.refreshMetadata();
        }
    }
}

@Component
@Slf4j
class CachingMetadataListener implements ApplicationListener<CachingMetadataChangeEvent> {
    @Autowired MetadataManagerProxy metadataManagerProxy;

    @Override
    public void onApplicationEvent(CachingMetadataChangeEvent cachingMetadataChangeEvent) {
        log.info("ACCEPT METADATA CHANGE EVENT!");
        // change the cache
        metadataManagerProxy.setCurrentMetadata((CachingMetadataManager) cachingMetadataChangeEvent.getSource());
    }
}
