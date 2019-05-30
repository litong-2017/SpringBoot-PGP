package com.kambaa.main;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.openpgp.PGPException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.ResourceUtils;

@Service
public class PGPServices {
	
	
	@Value("${privatekey.file.name}")
	String priKey;
	
	@Value("${publickey.file.name}")
	String pubKey;
	
	@Value("${privatekey.file.password}")
	String priKeyPassword;
	
	@Autowired
	PGPServices pgpServices;
	

	public String encryptMessage(String data) throws IOException, PGPException {
		
		
		 //the private key file
		 InputStream fis = new FileInputStream(ResourceUtils.getFile("classpath:"+pubKey));

		 ByteArrayOutputStream out = new ByteArrayOutputStream();
		 
		 //convert the data to input stream
		 InputStream stream = new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8));

		 //encrypt it!
		 PGPUtils.encryptStream(out, PGPUtils.readPublicKey(fis), stream);

		 //close all the stream
		 out.close();
		 stream.close();

		 return new String(out.toByteArray());

		}
	
	public String decryptMessage(String message) throws Exception {
		 
		 //trim it, just to be safe
		 message = message.trim();

		 ByteArrayOutputStream baos = new ByteArrayOutputStream();
		 
		 //convert encrypted message to input stream
		 ByteArrayInputStream bais = new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8));
		 
		 //public key file
		 InputStream fis = new FileInputStream(ResourceUtils.getFile("classpath:"+priKey));

		 // the real action. 'password1' is the passphrase
		 PGPUtils.decryptFile(bais, baos, fis, new String(priKeyPassword).toCharArray());
		 
		 //close all the stream
		 baos.close();
		 bais.close();
		 fis.close();
		 
		 //return the decrypted message
		 return new String(baos.toByteArray());

		}
	
	
	
}
