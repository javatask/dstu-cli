package org.example;

import org.apache.commons.cli.*;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.ua.DSTU4145NamedCurves;
import org.bouncycastle.asn1.ua.UAObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jcajce.provider.asymmetric.dstu.BCDSTU4145PrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.dstu.BCDSTU4145PublicKey;
import org.bouncycastle.jcajce.spec.DSTU4145ParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.JCEElGamalPrivateKey;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import sun.security.pkcs.PKCS8Key;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;

import static org.apache.commons.io.FileUtils.*;

public class Main {

    public static KeyPair generateKeyPair() throws InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchAlgorithmException, IOException {
        // keys
        ECDomainParameters ecDP = DSTU4145NamedCurves.getByOID(UAObjectIdentifiers.dstu4145le.branch("2.2"));
        ECCurve curve = ecDP.getCurve();

        // NOTE: For some reason this test uses an alternate base-point to the registry curve
        ecDP = new ECDomainParameters(curve,
                curve.createPoint(new BigInteger("BE6628EC3E67A91A4E470894FBA72B52C515F8AEE9", 16), new BigInteger("D9DEEDF655CF5412313C11CA566CDC71F4DA57DB45C", 16)),
                ecDP.getN(), ecDP.getH(), ecDP.getSeed());

        DSTU4145ParameterSpec spec = new DSTU4145ParameterSpec(ecDP);

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("DSTU4145", "BC");

        kpGen.initialize(spec);

        KeyPair keyPair = kpGen.generateKeyPair();

        writeByteArrayToFile(new File("priv.dat"), keyPair.getPrivate().getEncoded());
        writeByteArrayToFile(new File("pub.dat"), keyPair.getPublic().getEncoded());

        System.out.println("Key pair was generated");

        return keyPair;
    }

    public static PrivateKey loadPrivateKey(String fileName) throws InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchAlgorithmException, IOException {
        byte[] privateKeyRaw = readFileToByteArray(new File(fileName));

        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        PrivateKey privateKey = converter.getPrivateKey(PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(privateKeyRaw)));


        return privateKey;
    }

    public static PublicKey loadPublicKey(String fileName) throws InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchAlgorithmException, IOException {
        byte[] publicKeyRaw = readFileToByteArray(new File(fileName));

        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        PublicKey publicKey = converter.getPublicKey(SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(publicKeyRaw)));


        return publicKey;
    }

    public static byte[] sign(PrivateKey privKey, byte[] data) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException {
        Signature signatureProvcider = Signature.getInstance("GOST34311withDSTU4145", BouncyCastleProvider.PROVIDER_NAME);

        // sign
        signatureProvcider.initSign(privKey);
        signatureProvcider.update(data);
        byte[] signature = signatureProvcider.sign();

        writeByteArrayToFile(new File("signature.dat"), signature);

        return signature;
    }

    public static void verify(PublicKey pubKey, byte[] data, byte[] signature) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signatureProvcider = Signature.getInstance("GOST34311withDSTU4145", BouncyCastleProvider.PROVIDER_NAME);

        // verify
        signatureProvcider.initVerify(pubKey);
        signatureProvcider.update(data);
        boolean verify = signatureProvcider.verify(signature);

        System.out.printf("Signature is %s", verify);
    }

    public static void main(String[] args) throws NoSuchProviderException, NoSuchAlgorithmException, SignatureException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, ParseException {
        Security.addProvider(new BouncyCastleProvider());

        // create Options object
        Options options = new Options();
        // add t option
        options.addOption("g", false, "generate private and public keys");

        options.addOption("f", true, "file to sign");
        options.addOption("s", false, "sign the file");
        options.addOption("v", true, "verify signature");

        options.addOption("pub", true, "public key to use");
        options.addOption("pri", true, "private key to use");

        CommandLineParser parser = new GnuParser();
        CommandLine cmd = parser.parse(options, args);

        if (cmd.hasOption("g")) {
            KeyPair kp = generateKeyPair();
            return;
        }

        String fileToSign = cmd.getOptionValue("f");

        if (cmd.hasOption("f") && cmd.hasOption("s") && cmd.hasOption("pri")) {
            System.out.println("Signing file");
            byte[] data = readFileToByteArray(new File(fileToSign));

            PrivateKey privateKey = loadPrivateKey(cmd.getOptionValue("pri"));
            byte[] signature = sign(privateKey, data);
        }

        if (cmd.hasOption("f") && cmd.hasOption("v") && cmd.hasOption("pub")) {
            System.out.println("File verification");
            byte[] data = readFileToByteArray(new File(fileToSign));
            byte[] signature = readFileToByteArray(new File(cmd.getOptionValue("v")));

            PublicKey publicKey = loadPublicKey(cmd.getOptionValue("pub"));

            verify(publicKey, data, signature);
        }

    }
}
