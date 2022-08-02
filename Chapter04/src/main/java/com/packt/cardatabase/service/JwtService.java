package com.packt.cardatabase.service;

import java.security.Key;
import java.util.Date;

import javax.servlet.http.HttpServletRequest;

import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtService {
	static final long EXPIRATIONTIME = 86_400_000; // 1 day in ms
	static final String PREFIX = "Bearer";
	// Generate secret key. Only for the demonstration. You should read it from the application.conf
	static final Key KEY = Keys.secretKeyFor(SignatureAlgorithm.HS256);
	
	// Generate signed JWT token
	public String getToken(String username) {
		String token = Jwts.builder()
				.setSubject(username)
				.setExpiration(new Date(System.currentTimeMillis() + EXPIRATIONTIME))
				.signWith(KEY)
				.compact();
		
		return token;
	}
	// Get a token from request Authorization header, verify a token and get username
	public String getAuthUser(HttpServletRequest request) {
		String tokenString = request.getHeader(HttpHeaders.AUTHORIZATION);
		
		if(tokenString != null) {
			String user = Jwts.parserBuilder()
					.setSigningKey(KEY)
					.build()
					.parseClaimsJwt(tokenString.replace(PREFIX, ""))
					.getBody()
					.getSubject();
			
			if(user != null) return user;
		}
		return null;
	}
}
