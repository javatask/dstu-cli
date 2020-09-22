package org.example;

import org.apache.commons.cli.*;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.ua.DSTU4145NamedCurves;
import org.bouncycastle.asn1.ua.UAObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jcajce.provider.asymmetric.dstu.BCDSTU4145PrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.dstu.BCDSTU4145PublicKey;
import org.bouncycastle.jcajce.spec.DSTU4145ParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.JCEElGamalPrivateKey;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.*;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;


import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;

import static org.apache.commons.io.FileUtils.*;

public class Main2 {
    public static void main(String[] args) throws NoSuchProviderException, NoSuchAlgorithmException, SignatureException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, ParseException, CMSException {
        Security.addProvider(new BouncyCastleProvider());


        byte[] rawFile = readFileToByteArray(new File("test/signed.p7s"));
        CMSSignedData p7 = new CMSSignedData(rawFile);

        CMSSignedDataParser parser = new CMSSignedDataParser(new BcDigestCalculatorProvider(), rawFile);
        //parser.getSignerInfos().getSigners().
//
//        CMSSignatureAlgorithmNameGenerator alg = new DefaultCMSSignatureAlgorithmNameGenerator();
//        SignatureAlgorithmIdentifierFinder algFinder = new DefaultSignatureAlgorithmIdentifierFinder();
//        ContentVerifierProvider cvp = new ContentVerifierProvider() {
//            @Override
//            public boolean hasAssociatedCertificate() {
//                return true;
//            }
//
//            @Override
//            public X509CertificateHolder getAssociatedCertificate() {
//                return p7.getCertificates().getMatches(null);
//            }
//
//            @Override
//            public ContentVerifier get(AlgorithmIdentifier algorithmIdentifier) throws OperatorCreationException {
//                ContentVerifier cv = new ContentVerifier() {
//                    @Override
//                    public AlgorithmIdentifier getAlgorithmIdentifier() {
//                        return algorithmIdentifier;
//                    }
//
//                    @Override
//                    public OutputStream getOutputStream() {
//                        return p7.;
//                    }
//
//                    @Override
//                    public boolean verify(byte[] bytes) {
//                        return false;
//                    }
//                };
//                return null;
//            }
//        };
//        DigestCalculatorProvider digest = new BcDigestCalculatorProvider();
//        SignerInformationVerifier siv = new SignerInformationVerifier(alg,algFinder,cvp, digest);
//        SignerInformationVerifierProvider sivProvider = new SignerInformationVerifierProvider() {
//            @Override
//            public SignerInformationVerifier get(SignerId signerId) throws OperatorCreationException {
//                return siv;
//            }
//        };
//
//        JcaSimpleSignerInfoVerifierBuilder verf = new JcaSimpleSignerInfoVerifierBuilder();
//
//        p7.verifySignatures()
//
//        boolean b = p7.verifySignatures(sivProvider);
//        System.out.println("Signature");
//        System.out.println(b);
//
//        System.out.println("Test");

    }
}
