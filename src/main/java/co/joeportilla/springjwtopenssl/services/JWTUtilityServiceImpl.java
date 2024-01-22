package co.joeportilla.springjwtopenssl.services;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Base64;
import java.util.Date;

@Service
@RequiredArgsConstructor
public class JWTUtilityServiceImpl implements JWTUtilityService {

    @Value("classpath:jwtKeys/private_key.pem")
    private Resource privateKeyResource;

    @Value("classpath:jwtKeys/public_key.pem")
    private Resource publicKeyResource;

    @Override
    public String generateJWT(Long userId) throws IOException, NoSuchAlgorithmException,
                                                  InvalidKeySpecException, JOSEException {
        PrivateKey privateKey = loadPrivateKey(privateKeyResource);

        JWSSigner signer = new RSASSASigner(privateKey);

        Date now = new Date();

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                // Convert Long -> String
                .subject(userId.toString())
                // Set the time
                .issueTime(now)
                // Set the expiration time
                .expirationTime(new Date(now.getTime() + 14400000)) // token expirará después de 4 horas
                .build();

        // Instance
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSet);
        // Sign with the private key
        signedJWT.sign(signer);

        return signedJWT.serialize();
    }

    // lectura para validar jwt
    @Override
    public JWTClaimsSet parseJWT(String jwt) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException,
                                                    JOSEException, ParseException {
        PublicKey publicKey = loadPublicKey(publicKeyResource);

        // Parse the jwt
        SignedJWT signedJWT = SignedJWT.parse(jwt);

        // Instance the verifier, Cast publicKey to RSAPublicKey
        JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) publicKey);

        // Verify the jwt
        if (!signedJWT.verify(verifier)) {
            throw new JOSEException("Invalid signature");
        }

        // If the token is valid get claims
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

        // Verify the expiration date
        if (claimsSet.getExpirationTime().before(new Date())) {
            throw new JOSEException("Expired token");
        }

        // If the token is valid and has not expired, return the claims.
        return claimsSet;
    }

    private PrivateKey loadPrivateKey(Resource resource) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        byte[] keyBytes = Files.readAllBytes(Paths.get(resource.getURI()));
        // Limpiar
        String privateKeyPEM = new String(keyBytes, StandardCharsets.UTF_8)
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        // Decodificar
        byte[] decodedKey = Base64.getDecoder().decode(privateKeyPEM);
        // Conseguir la instancia
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decodedKey));
    }

    private PublicKey loadPublicKey(Resource resource) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = Files.readAllBytes(Paths.get(resource.getURI()));
        // Limpiar
        String publicKeyPEM = new String(keyBytes, StandardCharsets.UTF_8)
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        // Decodificar
        byte[] decodedKey = Base64.getDecoder().decode(publicKeyPEM);
        // Conseguir la instancia
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(new X509EncodedKeySpec(decodedKey));
    }
}
