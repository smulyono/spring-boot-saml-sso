package com.github.smulyono.samldemo.metadata;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEvent;
import org.springframework.security.saml.metadata.CachingMetadataManager;

@Slf4j
public class CachingMetadataChangeEvent extends ApplicationEvent {
    public CachingMetadataChangeEvent(Object source) {
        super(source);
        if (!(source instanceof CachingMetadataManager)) {
            log.error("Event is triggered with INCORRECT source object, expected CachineMetadataManager instance", source.getClass());
        }
    }
}

