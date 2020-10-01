package org.example;

import org.apache.commons.cli.*;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.ua.DSTU4145NamedCurves;
import org.bouncycastle.asn1.ua.UAObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.RC2Engine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jcajce.provider.asymmetric.dstu.BCDSTU4145PrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.dstu.BCDSTU4145PublicKey;
import org.bouncycastle.jcajce.spec.DSTU4145ParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.JCEElGamalPrivateKey;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.*;
import org.bouncycastle.pkcs.bc.BcPKCS12MacCalculatorBuilder;
import org.bouncycastle.pkcs.bc.BcPKCS12PBEOutputEncryptorBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS12SafeBagBuilder;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Calendar;
import java.util.Date;

import static org.apache.commons.io.FileUtils.*;

public class Main {

    public static void generateP12(PrivateKey privKey1, PublicKey pubKey1) throws CertificateException, OperatorCreationException, IOException, NoSuchAlgorithmException, PKCSException, NoSuchProviderException, SignatureException, InvalidKeyException {
        char[] passwd = "123456".toCharArray();
        X509Certificate[] chain = new X509Certificate[1];
        chain[0] =  getCertificate(privKey1, pubKey1);
        PublicKey         pubKey = pubKey1;
        PrivateKey        privKey = privKey1;
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        PKCS12SafeBagBuilder eeCertBagBuilder = new JcaPKCS12SafeBagBuilder(chain[0]);

        eeCertBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString("DSTU4145 Test"));
        eeCertBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, extUtils.createSubjectKeyIdentifier(pubKey));

        PKCS12SafeBagBuilder keyBagBuilder = new JcaPKCS12SafeBagBuilder(privKey, new BcPKCS12PBEOutputEncryptorBuilder(PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC, new CBCBlockCipher(new DESedeEngine())).build(passwd));

        keyBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString("DSTU4145 Test"));
        keyBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, extUtils.createSubjectKeyIdentifier(pubKey));

        //
        // construct the actual key store
        //
        PKCS12PfxPduBuilder pfxPduBuilder = new PKCS12PfxPduBuilder();

        PKCS12SafeBag[] certs = new PKCS12SafeBag[1];

        certs[0] = eeCertBagBuilder.build();

        pfxPduBuilder.addData(eeCertBagBuilder.build());

        pfxPduBuilder.addData(keyBagBuilder.build());

        PKCS12PfxPdu pfx = pfxPduBuilder.build(new BcPKCS12MacCalculatorBuilder(), passwd);


        writeByteArrayToFile(new File("dstu2.p12"), pfx.getEncoded());
    }

    public static X509Certificate getCertificate(PrivateKey privKey, PublicKey pubKey) throws OperatorCreationException, IOException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        Provider bcProvider = new BouncyCastleProvider();
        Security.addProvider(bcProvider);

        long now = System.currentTimeMillis();
        Date startDate = new Date(now);

        X500Name dnName = new X500Name("CN=Test Dstu4145");
        BigInteger certSerialNumber = new BigInteger(Long.toString(now)); // <-- Using the current timestamp as the certificate serial number

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(startDate);
        calendar.add(Calendar.YEAR, 1); // <-- 1 Yr validity1

        Date endDate = calendar.getTime();

        String signatureAlgorithm = "GOST34311WITHDSTU4145"; // <-- Use appropriate signature algorithm based on your keyPair algorithm.
        Signature.getInstance("GOST34311WITHDSTU4145", "BC");

        ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(privKey);

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(dnName, certSerialNumber, startDate, endDate, dnName, pubKey);

        // Extensions --------------------------

        // Basic Constraints
        BasicConstraints basicConstraints = new BasicConstraints(false); // <-- true for CA, false for EndEntity

        certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true, basicConstraints); // Basic Constraints is usually marked as critical.

        // -------------------------------------

        X509Certificate cert = new JcaX509CertificateConverter().setProvider(bcProvider).getCertificate(certBuilder.build(contentSigner));

        cert.verify(pubKey, "BC");

        return cert;
    }

    public static KeyPair generateKeyPair() throws InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchAlgorithmException, IOException, KeyStoreException, CertificateException, OperatorCreationException, PKCSException, SignatureException, InvalidKeyException {
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

        generateP12(keyPair.getPrivate(), keyPair.getPublic());

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
        Signature signatureProvcider = Signature.getInstance("GOST3411withDSTU4145", BouncyCastleProvider.PROVIDER_NAME);

        // sign
        signatureProvcider.initSign(privKey);
        signatureProvcider.update(data);
        byte[] signature = signatureProvcider.sign();

        writeByteArrayToFile(new File("signature.dat"), signature);

        return signature;
    }

    public static void verify(PublicKey pubKey, byte[] data, byte[] signature) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signatureProvcider = Signature.getInstance("GOST3411withDSTU4145", BouncyCastleProvider.PROVIDER_NAME);

        // verify
        signatureProvcider.initVerify(pubKey);
        signatureProvcider.update(data);
        boolean verify = signatureProvcider.verify(signature);

        System.out.printf("Signature is %s", verify);
    }

    public static void main(String[] args) throws NoSuchProviderException, NoSuchAlgorithmException, SignatureException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, ParseException, OperatorCreationException, CertificateException, PKCSException, KeyStoreException {
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
//            MessageDigest.getInstance("GOST34311");
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
            System.out.println("Signing file");
            byte[] data = readFileToByteArray(new File(fileToSign));
            byte[] signature = readFileToByteArray(new File(cmd.getOptionValue("v")));

            PublicKey publicKey = loadPublicKey(cmd.getOptionValue("pub"));

            verify(publicKey, data, signature);
        }

    }
}
