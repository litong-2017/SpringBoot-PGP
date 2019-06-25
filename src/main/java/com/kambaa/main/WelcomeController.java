package com.kambaa.main;

import java.util.Map;

import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class WelcomeController {

	
	@RequestMapping("/")
	public String WelcomeControllerGETMethod() {	
		return "Welcome to PGP encript service";
	}
	
	@RequestMapping(value="/",method=RequestMethod.POST)
	public String WelcomeControllerPOSTMethod() {	
		return "Welcome to PGP encript service";
	}
	
	@RequestMapping(value="/demo",method=RequestMethod.POST)
	public Object DemoPostMethod(@RequestBody Map<String, Object> payload) {	
		return payload;
	}
	
}
