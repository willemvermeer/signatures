package com.example;

import net.shibboleth.utilities.java.support.codec.Base64Support;
import org.apache.xml.security.c14n.Canonicalizer;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.config.JavaCryptoValidationInitializer;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.opensaml.xmlsec.signature.support.Signer;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class OpenSamlSignatures {

	private KeyPair keyPair;
	private FakeHSM fakeHSM;

	private OpenSamlSignatures() {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			this.keyPair = keyPairGenerator.generateKeyPair();
			this.fakeHSM = new FakeHSM(keyPair.getPrivate());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			System.exit(-1);
		}
	}

	public static void main(String[] args) throws Exception {
		// init the crypto stuff
		new JavaCryptoValidationInitializer().init();
		InitializationService.initialize();

		// read assertion and parse to Response object
		OpenSamlSignatures signatures = new OpenSamlSignatures();
		String assertion = signatures.readAssertion();
		Response response = signatures.parseResponse(assertion);
		String opensamlResult = signatures.signAndPrint(response);
		System.out.println("OpenSAML has signed the following Response:\n" + opensamlResult);
		signatures.verifySignature(opensamlResult);

		// now do the same thing without opensaml
		Document doc = signatures.parseDocument(assertion);
		String digestValue = signatures.generateBase64EncodedDigestValue(doc);
		String signedInfoSection = signatures.createSignedInfo(digestValue);
		String signatureValue = signatures.generateBase64EncodedSignatureValue(signedInfoSection);
		String signatureSection = signatures.createSignature(signatureValue, signedInfoSection);
		signatures.mergeSignatureIntoDocument(doc, signatureSection);
		String endResult = signatures.docToStr(doc);
		System.out.println("Handmade signature end result\n" + endResult);
		signatures.verifySignature(endResult);
	}

	private void mergeSignatureIntoDocument(Document doc, String signatureSection) throws Exception {
		Document signatureDoc = parseDocument(signatureSection);
		Node importedNode = doc.importNode(signatureDoc.getFirstChild(), true);
		// the Signature MUST be inserted between the Issuer and Status child nodes - we are assuming here that Issuer is always present
		doc.getFirstChild().insertBefore(importedNode, doc.getFirstChild().getChildNodes().item(2));
	}

	private String generateBase64EncodedSignatureValue(String signedInfoSection) throws Exception {
		Document signatureInfoNode = parseDocument(signedInfoSection);
		return fakeHSM.sign(signatureInfoNode.getDocumentElement());
	}

	private void verifySignature(String signedResponse) throws Exception {
		Response parsedResponse = parseResponse(signedResponse);
		Credential credential = new BasicCredential(keyPair.getPublic(), keyPair.getPrivate());
		SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
		profileValidator.validate(parsedResponse.getSignature());
		SignatureValidator.validate(parsedResponse.getSignature(), credential);
		System.out.println("Signature validation passed.");
	}

	private String signAndPrint(Response response) throws Exception {
		Signature signature = buildSAMLObject(Signature.class);
		Credential credential = new BasicCredential(keyPair.getPublic(), keyPair.getPrivate());
		signature.setSigningCredential(credential);
		signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
		signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

		response.setSignature(signature);
		XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(response).marshall(response);
		Signer.signObject(signature);
		return printSaml(response);
	}

	private String readAssertion() throws Exception {
		byte[] data = Files.readAllBytes(Paths.get(this.getClass().getClassLoader().getResource("assertion.xml").toURI()));
		return new String(data, StandardCharsets.UTF_8).replace("\n", "").replace("\t", "");
	}

	private String generateBase64EncodedDigestValue(Document doc) throws Exception {
		// canonicalize to byte[]
		byte[] canonicalizedResponse = getCanonicalizer().canonicalizeSubtree(doc.getDocumentElement());

		// get a SHA-256 digest value
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		byte[] hashedCanonicalizedResponse = digest.digest(canonicalizedResponse);

		String readableHash = baseEncode(hashedCanonicalizedResponse);
		System.out.println("Readable hash=" + readableHash);
		return readableHash;
	}

	private Response parseResponse(String response) throws Exception {
		// first parse the XML
		Document doc = parseDocument(response);

		// convert to Response object
		return (Response) XMLObjectProviderRegistrySupport.getUnmarshallerFactory().getUnmarshaller(doc.getDocumentElement()).unmarshall(doc.getDocumentElement());
	}

	private Document parseDocument(String response) throws Exception {
		DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
		dbFactory.setNamespaceAware(true); // don't forget this!
		DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
		return dBuilder.parse(new ByteArrayInputStream(response.getBytes(StandardCharsets.UTF_8)));
	}

	private String docToStr(Document doc) throws Exception {
		StringWriter sw = new StringWriter();
		TransformerFactory transformerFactory = TransformerFactory.newInstance();
		Transformer transformer = transformerFactory.newTransformer();
		transformer.transform(new DOMSource(doc), new StreamResult(sw));
		return sw.toString();
	}

	private static <T> T buildSAMLObject(final Class<T> clazz) throws Exception {
		XMLObjectBuilderFactory builderFactory =
			XMLObjectProviderRegistrySupport.getBuilderFactory();
		QName defaultElementName = (QName) clazz.getDeclaredField( "DEFAULT_ELEMENT_NAME").get(null);
		T object = (T) builderFactory.getBuilder(defaultElementName).buildObject(defaultElementName);
		return object;
	}

	private String printSaml(XMLObject xmlObject) throws Exception {
		StringWriter sw = new StringWriter();
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setNamespaceAware(true);
		DocumentBuilder builder = factory.newDocumentBuilder();
		Document doc = builder.newDocument();
		XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(xmlObject).marshall(xmlObject, doc);
		Transformer transformer = TransformerFactory.newInstance().newTransformer();
		transformer.setOutputProperty(OutputKeys.INDENT, "no");
		StreamResult result = new StreamResult(sw);
		DOMSource source = new DOMSource(doc);
		transformer.transform(source, result);
		return sw.toString();
	}

	private Canonicalizer canonicalizer = null;
	private Canonicalizer getCanonicalizer() throws Exception {
		if (canonicalizer == null) {
			canonicalizer = Canonicalizer.getInstance(CanonicalizationMethod.EXCLUSIVE);
		}
		return canonicalizer;
	}

	static String baseEncode(byte[] bytes) {
		return Base64Support.encode(bytes, false);
	}

	private String createSignedInfo(String readableHash) {
		return "<ds:SignedInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                 "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                 "<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\n" +
			     "<ds:Reference URI=\"#1a3f38aac4327c6a8bfa6104ef220d38\">\n" +
				   "<ds:Transforms>\n" +
				     "<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n" +
				     "<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
				   "</ds:Transforms>\n" +
				   "<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n" +
				   "<ds:DigestValue>" + readableHash + "</ds:DigestValue>\n" +
			     "</ds:Reference>\n" +
			   "</ds:SignedInfo>";
	}

	private String createSignature(String signatureValue, String signedInfo) {
		return "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">" +
				signedInfo + "<ds:SignatureValue>" + signatureValue + "</ds:SignatureValue></ds:Signature>";
	}

}
