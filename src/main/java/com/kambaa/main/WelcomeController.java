package com.kambaa.main;

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
	
}
