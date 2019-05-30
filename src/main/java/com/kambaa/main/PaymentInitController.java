package com.kambaa.main;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PaymentInitController {
	
		
	@Value("${default.raw.response}")
	private String rawResponse;
	
	@Autowired
	PGPServices pgpServices;
		
	Logger logger=LoggerFactory.getLogger(PaymentInitController.class);
		
	@RequestMapping(value="/paymentinitiation",method=RequestMethod.POST)
	public String paymentInitiation(@RequestBody String request,String response){
		logger.info("-------------PAYMENT INIT REQUEST START HERE ------------------------");
		try {
			logger.info("Request Decription Start");
			String getResponse= pgpServices.decryptMessage(request);
			logger.info("Payment init Request Received As :"+getResponse);
			
			logger.info("Response Prepration start");
			response=pgpServices.encryptMessage(rawResponse);
			logger.info("Response send to requester :"+response);	
			
		}catch (Exception e) {
			logger.error("Error occured when payment Init :"+e);
			response="Something went wrong";
		}
		logger.info("-------------PAYMENT INIT REQUEST END HERE ------------------------");
		return response;		
	}
			
	@RequestMapping(value="/paymentinitiation/setresponse",method=RequestMethod.POST)
	public String paymentInitiationSetResponse(@RequestBody String request){
		logger.info("---------- PAYMENT INIT RESPONSE SET CONTROLLER START HERE -----------");
		logger.info("Previous Response Value :"+rawResponse);
		rawResponse=request;
		logger.info("New Response value :"+rawResponse);
		logger.info("---------- PAYMENT INIT RESPONSE SET CONTROLLER END HERE -----------");
		return "Response set success";		
	}
	
	
	@RequestMapping(value="/paymentinitiation/viewresponse",method=RequestMethod.GET)
	public String paymentInitiationViewResponse(){
		logger.info("---------- PAYMENT INIT RESPONSE VIEW CONTROLLER START HERE -----------");
		logger.info("Response value :"+rawResponse);		
		logger.info("---------- PAYMENT INIT RESPONSE VIEW CONTROLLER END HERE -----------");
		return rawResponse;		
	}

}
