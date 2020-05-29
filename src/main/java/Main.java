
import org.bouncycastle.asn1.ua.DSTU4145NamedCurves;
import org.bouncycastle.asn1.ua.UAObjectIdentifiers;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jcajce.spec.DSTU4145ParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECCurve;

import java.math.BigInteger;
import java.security.*;

public class Main {

    public static void main(String[] args) throws NoSuchProviderException, NoSuchAlgorithmException, SignatureException, InvalidAlgorithmParameterException, InvalidKeyException {
        Security.addProvider(new BouncyCastleProvider());

        Signature signatureProvcider = Signature.getInstance("GOST3411withDSTU4145", BouncyCastleProvider.PROVIDER_NAME);

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

        // sign
        signatureProvcider.initSign(keyPair.getPrivate());
        byte[] message = new byte[]{(byte)'a', (byte)'b', (byte)'c'};
        signatureProvcider.update(message);
        byte[] signature = signatureProvcider.sign();

        // verify
        signatureProvcider.initVerify(keyPair.getPublic());
        signatureProvcider.update(message);
        boolean verify = signatureProvcider.verify(signature);

        System.out.printf("Signature is %s", verify);
    }
}
