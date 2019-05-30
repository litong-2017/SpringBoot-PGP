package com.kambaa.main;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class PGPConfiguration {
	
	@Bean
	public PGPUtils getPGPUtils() {
		return new PGPUtils();
	}
	
}
