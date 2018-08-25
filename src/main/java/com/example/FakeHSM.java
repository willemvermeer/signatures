package com.example;

import org.apache.xml.security.c14n.Canonicalizer;
import org.w3c.dom.Element;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.security.PrivateKey;

public class FakeHSM {

	private PrivateKey privateKey;

	public FakeHSM(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}

	public String sign(Element signedInfoNode) throws Exception {
		java.security.Signature signature = java.security.Signature.getInstance("SHA256withRSA");
		signature.initSign(privateKey);

		Canonicalizer c14n = Canonicalizer.getInstance(CanonicalizationMethod.EXCLUSIVE);
		byte[] canonicalizedSignedInfo = c14n.canonicalizeSubtree(signedInfoNode);
		signature.update(canonicalizedSignedInfo);
		byte[] signedBytes = signature.sign();
		return OpenSamlSignatures.baseEncode(signedBytes);
	}
}
