package com.kambaa.main;

import org.bouncycastle.openpgp.PGPException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class EncriptionDecryptionController {

	
	@Autowired
	PGPServices pgpServices;
	
	Logger logger=LoggerFactory.getLogger(EncriptionDecryptionController.class);
		
	@RequestMapping(value="/encript",method=RequestMethod.POST)
	public String encript(@RequestBody String request,String response) throws PGPException{
		logger.info("-------------ENCRYPTION CONTROLLER START HERE-----------");
		try {
			response=pgpServices.encryptMessage(request);
		}catch (Exception e) {
			logger.error("Error occured when encript Request :"+e);
			response="Error occured when Encript";
		}
		logger.info("-------------ENCRYPTION CONTROLLER END HERE-----------");
		return response;
	}
	
	@RequestMapping(value="/decript",method=RequestMethod.POST)
	public String decript(@RequestBody String request,String response){
		logger.info("-------------DECRYPTION CONTROLLER START HERE-----------");
		try {
			logger.info("Decription Request received as :"+request);
			response= pgpServices.decryptMessage(request);
			logger.info("Decripted request is :"+response);
			
		}catch (Exception e) {
			logger.error("Error occured when Decrypt :"+e);
			response="Error occured when Decrypt the PGP Message";
		}
		logger.info("-------------DECRYPTION CONTROLLER END HERE-----------");
		return response;		
	}
	
	
}
